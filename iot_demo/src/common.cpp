#include "common.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace iotproto {

void sodium_init_or_throw() {
    if (sodium_init() < 0) {
        throw std::runtime_error("sodium_init() failed");
    }
}

ByteVec random_bytes(size_t n) {
    ByteVec out(n);
    randombytes_buf(out.data(), out.size());
    return out;
}

std::string hex_encode(const unsigned char* data, size_t len) {
    std::string out(len * 2, '\0');
    sodium_bin2hex(out.data(), out.size() + 1, data, len);
    return out;
}

std::string hex_encode(const ByteVec& v) {
    return hex_encode(v.data(), v.size());
}

ByteVec hex_decode(const std::string& hex) {
    ByteVec out(hex.size() / 2 + 1);
    size_t bin_len = 0;
    if (sodium_hex2bin(out.data(), out.size(), hex.c_str(), hex.size(), nullptr, &bin_len, nullptr) != 0) {
        throw std::runtime_error("invalid hex string: " + hex);
    }
    out.resize(bin_len);
    return out;
}

ByteVec str_bytes(const std::string& s) {
    return ByteVec(s.begin(), s.end());
}

std::string bytes_str(const ByteVec& v) {
    return std::string(v.begin(), v.end());
}

ByteVec concat(const std::vector<ByteVec>& parts) {
    size_t total = 0;
    for (const auto& p : parts) total += p.size();
    ByteVec out;
    out.reserve(total);
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

ByteVec hash32(const ByteVec& data) {
    ByteVec out(HASH32_LEN);
    crypto_generichash(out.data(), out.size(), data.data(), data.size(), nullptr, 0);
    return out;
}

ByteVec hash32_parts(const std::vector<ByteVec>& parts) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, HASH32_LEN);
    for (const auto& p : parts) {
        crypto_generichash_update(&st, p.data(), p.size());
    }
    ByteVec out(HASH32_LEN);
    crypto_generichash_final(&st, out.data(), out.size());
    return out;
}

ByteVec hash_salt16(const std::string& hwid) {
    ByteVec h = hash32(str_bytes(hwid));
    h.resize(crypto_pwhash_SALTBYTES);
    return h;
}

ByteVec xor_fixed(const ByteVec& a, const ByteVec& b) {
    if (a.size() != b.size()) throw std::runtime_error("xor_fixed: length mismatch");
    ByteVec out(a.size());
    for (size_t i = 0; i < a.size(); ++i) out[i] = a[i] ^ b[i];
    return out;
}

static ByteVec hmac_sha256(const ByteVec& key, const ByteVec& msg) {
    ByteVec out(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key.data(), key.size());
    crypto_auth_hmacsha256_update(&st, msg.data(), msg.size());
    crypto_auth_hmacsha256_final(&st, out.data());
    return out;
}

ByteVec hkdf_sha256(const ByteVec& ikm, const ByteVec& salt, const ByteVec& info, size_t out_len) {
    ByteVec actual_salt = salt;
    if (actual_salt.empty()) actual_salt.assign(crypto_auth_hmacsha256_BYTES, 0x00);
    ByteVec prk = hmac_sha256(actual_salt, ikm);

    ByteVec okm;
    okm.reserve(out_len);
    ByteVec prev;
    unsigned char counter = 1;
    while (okm.size() < out_len) {
        ByteVec input;
        input.insert(input.end(), prev.begin(), prev.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter++);
        prev = hmac_sha256(prk, input);
        okm.insert(okm.end(), prev.begin(), prev.end());
    }
    okm.resize(out_len);
    sodium_memzero(prk.data(), prk.size());
    sodium_memzero(prev.data(), prev.size());
    return okm;
}

ByteVec pbkdf_password_key(const std::string& password, const std::string& hwid) {
    ByteVec key(KEY_LEN);
    ByteVec salt = hash_salt16(hwid);
    if (crypto_pwhash(key.data(), key.size(), password.c_str(), password.size(), salt.data(),
                      crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("crypto_pwhash failed; insufficient memory?");
    }
    return key;
}

ByteVec aead_encrypt(const ByteVec& key, const ByteVec& plaintext, const ByteVec& aad) {
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("aead_encrypt: key must be 32 bytes");
    }
    ByteVec nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    ByteVec c(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        c.data(), &clen,
        plaintext.data(), plaintext.size(),
        aad.empty() ? nullptr : aad.data(), aad.size(),
        nullptr, nonce.data(), key.data());
    c.resize(static_cast<size_t>(clen));
    ByteVec blob;
    blob.reserve(nonce.size() + c.size());
    blob.insert(blob.end(), nonce.begin(), nonce.end());
    blob.insert(blob.end(), c.begin(), c.end());
    return blob;
}

ByteVec aead_decrypt(const ByteVec& key, const ByteVec& ciphertext_blob, const ByteVec& aad) {
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("aead_decrypt: key must be 32 bytes");
    }
    const size_t nlen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const size_t ab = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (ciphertext_blob.size() < nlen + ab) throw std::runtime_error("ciphertext too short");
    const unsigned char* nonce = ciphertext_blob.data();
    const unsigned char* c = ciphertext_blob.data() + nlen;
    size_t clen_sz = ciphertext_blob.size() - nlen;
    ByteVec m(clen_sz - ab);
    unsigned long long mlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            m.data(), &mlen, nullptr,
            c, clen_sz,
            aad.empty() ? nullptr : aad.data(), aad.size(),
            nonce, key.data()) != 0) {
        throw std::runtime_error("AEAD authentication failed");
    }
    m.resize(static_cast<size_t>(mlen));
    return m;
}

ByteVec u64be(uint64_t x) {
    ByteVec out(8);
    for (int i = 7; i >= 0; --i) {
        out[7 - i] = static_cast<unsigned char>((x >> (i * 8)) & 0xff);
    }
    return out;
}

uint64_t read_u64be(const ByteVec& v, size_t offset) {
    if (v.size() < offset + 8) throw std::runtime_error("read_u64be: too short");
    uint64_t x = 0;
    for (size_t i = 0; i < 8; ++i) x = (x << 8) | v[offset + i];
    return x;
}

uint64_t unix_time_seconds() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

uint64_t monotonic_time_ns() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());
}

double ns_to_ms(uint64_t ns) {
    return static_cast<double>(ns) / 1000000.0;
}

std::string format_ms(uint64_t ns) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(3) << ns_to_ms(ns);
    return oss.str();
}

std::string trim(const std::string& s) {
    const char* ws = " \t\r\n";
    size_t b = s.find_first_not_of(ws);
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

std::map<std::string, std::string> load_kv_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open file: " + path);
    std::map<std::string, std::string> kv;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        size_t pos = line.find('=');
        if (pos == std::string::npos) continue;
        kv[trim(line.substr(0, pos))] = trim(line.substr(pos + 1));
    }
    return kv;
}

void save_kv_file(const std::string& path, const std::map<std::string, std::string>& kv) {
    std::ofstream out(path, std::ios::trunc);
    if (!out) throw std::runtime_error("cannot write file: " + path);
    out << "# Generated by iot_mincosig_demo. Values are hex unless documented otherwise.\n";
    for (const auto& [k, v] : kv) {
        out << k << "=" << v << "\n";
    }
}

std::string required_value(const std::map<std::string, std::string>& kv, const std::string& key) {
    auto it = kv.find(key);
    if (it == kv.end() || it->second.empty()) throw std::runtime_error("missing config key: " + key);
    return it->second;
}

std::string read_hwid_from_cpuinfo() {
#ifndef _WIN32
    std::ifstream in("/proc/cpuinfo");
    if (!in) throw std::runtime_error("cannot open /proc/cpuinfo");
    std::string line;
    while (std::getline(in, line)) {
        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        if (lower.rfind("serial", 0) == 0 || lower.find("serial") != std::string::npos) {
            size_t pos = line.find(':');
            if (pos != std::string::npos) {
                std::string serial = trim(line.substr(pos + 1));
                if (!serial.empty()) return serial;
            }
        }
    }
    throw std::runtime_error("CPU Serial not found in /proc/cpuinfo; pass --hwid manually or adjust read_hwid_from_cpuinfo()");
#else
    throw std::runtime_error("/proc/cpuinfo is not available on Windows; pass --hwid");
#endif
}

} // namespace iotproto
