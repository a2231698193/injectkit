// payload/json.hpp —— 极简 JSON（只为 RPC 服务，不求通用）
//
// 为什么自己写而不是用第三方库
// ===========================
// 1. payload 跑在目标进程里，每多一个依赖就多一份体积和特征
// 2. 我们只需要一个子集：解析命令、序列化结果
// 3. 不依赖 CRT（注入环境不保证，manual map 情况下根本没有）
//
// 支持范围
// ========
//   解析：object / array / string / number / true / false / null
//   序列化：同上（字符串转义处理完整）
//   不支持：���嵌套限制（这里限 8 层防栈溢出）
//
// 不使用 std::string / std::vector 的地方：
//   需要一个「不依赖 CRT」的版本时用 Arena 分配。
//   当前会用到 std::string 是为了可用性，后续 P3 会出无 CRT 版本。
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace json {

// ---------- 值类型 ----------
enum class Type : uint8_t { Null, Bool, Number, String, Array, Object };

class Value {
public:
    Value() = default;
    explicit Value(bool b) : type_(Type::Bool), bool_(b) {}
    explicit Value(double n) : type_(Type::Number), num_(n) {}
    explicit Value(int n) : type_(Type::Number), num_(static_cast<double>(n)) {}
    explicit Value(int64_t n) : type_(Type::Number), num_(static_cast<double>(n)) {}
    explicit Value(uint64_t n) : type_(Type::Number), num_(static_cast<double>(n)) {}
    explicit Value(const char* s) : type_(Type::String), str_(s ? s : "") {}
    explicit Value(std::string s) : type_(Type::String), str_(std::move(s)) {}

    static Value null() { return Value(); }
    static Value array() { Value v; v.type_ = Type::Array; return v; }
    static Value object() { Value v; v.type_ = Type::Object; return v; }

    Type type() const noexcept { return type_; }
    bool is_null() const noexcept { return type_ == Type::Null; }
    bool is_object() const noexcept { return type_ == Type::Object; }
    bool is_array() const noexcept { return type_ == Type::Array; }

    bool as_bool(bool def = false) const noexcept {
        if (type_ == Type::Bool) return bool_;
        if (type_ == Type::Number) return num_ != 0;
        return def;
    }

    double as_number(double def = 0) const noexcept {
        if (type_ == Type::Number) return num_;
        if (type_ == Type::Bool) return bool_ ? 1 : 0;
        return def;
    }

    int64_t as_int(int64_t def = 0) const noexcept {
        if (type_ != Type::Number && type_ != Type::Bool) return def;
        return static_cast<int64_t>(as_number());
    }

    // 支持 "0x1234" 这种十六进制（RPC 传地址用）
    uint64_t as_addr(uint64_t def = 0) const noexcept {
        if (type_ != Type::String) return static_cast<uint64_t>(as_int(static_cast<int64_t>(def)));
        const char* s = str_.c_str();
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            return strtoull(s + 2, nullptr, 16);
        }
        return strtoull(s, nullptr, 10);
    }

    const std::string& as_string() const noexcept { return str_; }

    // ---- 对象 ----
    Value& set(const std::string& key, Value v) {
        if (type_ != Type::Object) { type_ = Type::Object; arr_.clear(); }
        for (auto& kv : arr_) {
            if (kv.first == key) { kv.second = std::move(v); return *this; }
        }
        arr_.emplace_back(key, std::move(v));
        return *this;
    }

    const Value* get(const std::string& key) const noexcept {
        if (type_ != Type::Object) return nullptr;
        for (const auto& kv : arr_) {
            if (kv.first == key) return &kv.second;
        }
        return nullptr;
    }

    // 带默认值的取值
    std::string get_str(const std::string& key, const char* def = "") const {
        const Value* v = get(key);
        return v ? v->as_string() : std::string(def);
    }

    uint64_t get_addr(const std::string& key, uint64_t def = 0) const {
        const Value* v = get(key);
        return v ? v->as_addr(def) : def;
    }

    int64_t get_int(const std::string& key, int64_t def = 0) const {
        const Value* v = get(key);
        return v ? v->as_int(def) : def;
    }

    // ---- 数组 ----
    Value& push(Value v) {
        if (type_ != Type::Array) { type_ = Type::Array; arr_.clear(); }
        arr_.emplace_back(std::string(), std::move(v));
        return *this;
    }

    size_t size() const noexcept { return arr_.size(); }

    const Value& at(size_t i) const noexcept {
        static const Value kNull;
        return i < arr_.size() ? arr_[i].second : kNull;
    }

    // ---- 序列化 ----
    std::string dump() const {
        std::string out;
        out.reserve(128);
        write(out);
        return out;
    }

private:
    void write(std::string& out) const {
        switch (type_) {
            case Type::Null: out += "null"; break;
            case Type::Bool: out += bool_ ? "true" : "false"; break;
            case Type::Number: {
                char buf[32];
                const double n = num_;
                // 整数不带小数点
                if (n == static_cast<double>(static_cast<int64_t>(n)) &&
                    n > -1e15 && n < 1e15) {
                    snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(n));
                } else {
                    snprintf(buf, sizeof(buf), "%.17g", n);
                }                out += buf;
                break;
            }
            case Type::String: write_string(out, str_); break;
            case Type::Array: {
                out += '[';
                for (size_t i = 0; i < arr_.size(); ++i) {
                    if (i) out += ',';
                    arr_[i].second.write(out);
                }
                out += ']';
                break;
            }
            case Type::Object: {
                out += '{';
                bool first = true;
                for (const auto& kv : arr_) {
                    if (!first) out += ',';
                    first = false;
                    write_string(out, kv.first);
                    out += ':';
                    kv.second.write(out);
                }
                out += '}';
                break;
            }
        }
    }

    static void write_string(std::string& out, const std::string& s) {
        out += '"';
        for (unsigned char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                default:
                    if (c < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", c);
                        out += buf;
                    } else {
                        out += static_cast<char>(c);
                    }
            }
        }
        out += '"';
    }

    Type type_ = Type::Null;
    bool bool_ = false;
    double num_ = 0;
    std::string str_;
    // object 用 (key, value)；array 用 ("", value)
    std::vector<std::pair<std::string, Value>> arr_;
};

// ---------- 解析 ----------
class Parser {
public:
    explicit Parser(const char* s, size_t n) : p_(s), end_(s + n) {}

    bool parse(Value& out) {
        skip_ws();
        if (!parse_value(out, 0)) return false;
        skip_ws();
        return p_ == end_;   // 必须正好用完
    }

private:
    static constexpr int kMaxDepth = 8;

    void skip_ws() {
        while (p_ < end_ && (*p_ == ' ' || *p_ == '\t' || *p_ == '\n' || *p_ == '\r')) ++p_;
    }

    bool parse_value(Value& out, int depth) {
        if (depth > kMaxDepth || p_ >= end_) return false;

        switch (*p_) {
            case '{': return parse_object(out, depth);
            case '[': return parse_array(out, depth);
            case '"': {
                std::string s;
                if (!parse_string(s)) return false;
                out = Value(std::move(s));
                return true;
            }
            case 't':
                if (match("true")) { out = Value(true); return true; }
                return false;
            case 'f':
                if (match("false")) { out = Value(false); return true; }
                return false;
            case 'n':
                if (match("null")) { out = Value::null(); return true; }
                return false;
            default:
                return parse_number(out);
        }
    }

    bool match(const char* lit) {
        const size_t n = strlen(lit);
        if (static_cast<size_t>(end_ - p_) < n) return false;
        if (memcmp(p_, lit, n) != 0) return false;
        p_ += n;
        return true;
    }

    bool parse_object(Value& out, int depth) {
        ++p_;   // '{'
        out = Value::object();
        skip_ws();
        if (p_ < end_ && *p_ == '}') { ++p_; return true; }

        for (;;) {
            skip_ws();
            if (p_ >= end_ || *p_ != '"') return false;

            std::string key;
            if (!parse_string(key)) return false;

            skip_ws();
            if (p_ >= end_ || *p_ != ':') return false;
            ++p_;

            skip_ws();
            Value v;
            if (!parse_value(v, depth + 1)) return false;
            out.set(key, std::move(v));

            skip_ws();
            if (p_ >= end_) return false;
            if (*p_ == ',') { ++p_; continue; }
            if (*p_ == '}') { ++p_; return true; }
            return false;
        }
    }

    bool parse_array(Value& out, int depth) {
        ++p_;   // '['
        out = Value::array();
        skip_ws();
        if (p_ < end_ && *p_ == ']') { ++p_; return true; }

        for (;;) {
            skip_ws();
            Value v;
            if (!parse_value(v, depth + 1)) return false;
            out.push(std::move(v));

            skip_ws();
            if (p_ >= end_) return false;
            if (*p_ == ',') { ++p_; continue; }
            if (*p_ == ']') { ++p_; return true; }
            return false;
        }
    }

    bool parse_string(std::string& out) {
        ++p_;   // '"'
        out.clear();
        while (p_ < end_) {
            const char c = *p_++;
            if (c == '"') return true;
            if (c != '\\') { out += c; continue; }

            if (p_ >= end_) return false;
            const char esc = *p_++;
            switch (esc) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'u': {
                    if (end_ - p_ < 4) return false;
                    char hex[5] = {p_[0], p_[1], p_[2], p_[3], 0};
                    p_ += 4;
                    const unsigned cp = static_cast<unsigned>(strtoul(hex, nullptr, 16));
                    // 只处理 BMP 的 ASCII 部分，其余替换为 '?'
                    if (cp < 0x80) out += static_cast<char>(cp);
                    else out += '?';
                    break;
                }
                default: return false;
            }
        }
        return false;
    }

    bool parse_number(Value& out) {
        const char* start = p_;
        if (p_ < end_ && (*p_ == '-' || *p_ == '+')) ++p_;
        bool any = false;
        while (p_ < end_ && *p_ >= '0' && *p_ <= '9') { ++p_; any = true; }
        if (p_ < end_ && *p_ == '.') {
            ++p_;
            while (p_ < end_ && *p_ >= '0' && *p_ <= '9') { ++p_; any = true; }
        }
        if (any && p_ < end_ && (*p_ == 'e' || *p_ == 'E')) {
            ++p_;
            if (p_ < end_ && (*p_ == '-' || *p_ == '+')) ++p_;
            while (p_ < end_ && *p_ >= '0' && *p_ <= '9') ++p_;
        }
        if (!any) return false;

        std::string tmp(start, static_cast<size_t>(p_ - start));
        out = Value(strtod(tmp.c_str(), nullptr));
        return true;
    }

    const char* p_;
    const char* end_;
};

inline bool parse(const char* s, size_t n, Value& out) {
    Parser p(s, n);
    return p.parse(out);
}

inline bool parse(const std::string& s, Value& out) {
    return parse(s.data(), s.size(), out);
}

}  // namespace json
