#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include <sodium.h>

namespace iotproto {

using ByteVec = std::vector<unsigned char>;

constexpr size_t HASH32_LEN = 32;
constexpr size_t SALT_LEN = 32;
constexpr size_t NONCE_LEN = 16;
constexpr size_t X25519_PK_LEN = crypto_box_PUBLICKEYBYTES;
constexpr size_t X25519_SK_LEN = crypto_box_SECRETKEYBYTES;
constexpr size_t ED25519_PK_LEN = crypto_sign_PUBLICKEYBYTES;
constexpr size_t ED25519_SK_LEN = crypto_sign_SECRETKEYBYTES;
constexpr size_t ED25519_SIG_LEN = crypto_sign_BYTES;
constexpr size_t ED25519_POINT_LEN = crypto_core_ed25519_BYTES;
constexpr size_t ED25519_SCALAR_LEN = crypto_core_ed25519_SCALARBYTES;
constexpr size_t KEY_LEN = 32;

void sodium_init_or_throw();

ByteVec random_bytes(size_t n);
std::string hex_encode(const unsigned char* data, size_t len);
std::string hex_encode(const ByteVec& v);
ByteVec hex_decode(const std::string& hex);

ByteVec str_bytes(const std::string& s);
std::string bytes_str(const ByteVec& v);

ByteVec hash32(const ByteVec& data);
ByteVec hash32_parts(const std::vector<ByteVec>& parts);
ByteVec hash_salt16(const std::string& hwid);

ByteVec xor_fixed(const ByteVec& a, const ByteVec& b);
ByteVec hkdf_sha256(const ByteVec& ikm, const ByteVec& salt, const ByteVec& info, size_t out_len = KEY_LEN);
ByteVec pbkdf_password_key(const std::string& password, const std::string& hwid);

ByteVec aead_encrypt(const ByteVec& key, const ByteVec& plaintext, const ByteVec& aad = {});
ByteVec aead_decrypt(const ByteVec& key, const ByteVec& ciphertext_blob, const ByteVec& aad = {});

ByteVec u64be(uint64_t x);
uint64_t read_u64be(const ByteVec& v, size_t offset = 0);
uint64_t unix_time_seconds();
uint64_t monotonic_time_ns();
double ns_to_ms(uint64_t ns);
std::string format_ms(uint64_t ns);

std::string trim(const std::string& s);
std::map<std::string, std::string> load_kv_file(const std::string& path);
void save_kv_file(const std::string& path, const std::map<std::string, std::string>& kv);
std::string required_value(const std::map<std::string, std::string>& kv, const std::string& key);

std::string read_hwid_from_cpuinfo();

ByteVec concat(const std::vector<ByteVec>& parts);

} // namespace iotproto
