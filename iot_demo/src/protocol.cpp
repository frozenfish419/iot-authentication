#include "protocol.hpp"

namespace iotproto {

void require_len(const ByteVec& v, size_t n, const std::string& name) {
    if (v.size() != n) throw std::runtime_error(name + " length mismatch");
}

DefaultKeyPair ed25519_keypair() {
    DefaultKeyPair kp;
    kp.pub.resize(ED25519_PK_LEN);
    kp.sec.resize(ED25519_SK_LEN);
    crypto_sign_keypair(kp.pub.data(), kp.sec.data());
    return kp;
}

ByteVec sign_ed25519(const ByteVec& message, const ByteVec& secret_key) {
    require_len(secret_key, ED25519_SK_LEN, "Ed25519 secret key");
    ByteVec sig(ED25519_SIG_LEN);
    unsigned long long siglen = 0;
    if (crypto_sign_detached(sig.data(), &siglen, message.data(), message.size(), secret_key.data()) != 0 || siglen != ED25519_SIG_LEN) {
        throw std::runtime_error("crypto_sign_detached failed");
    }
    return sig;
}

bool verify_ed25519(const ByteVec& message, const ByteVec& sig, const ByteVec& public_key) {
    if (sig.size() != ED25519_SIG_LEN || public_key.size() != ED25519_PK_LEN) return false;
    return crypto_sign_verify_detached(sig.data(), message.data(), message.size(), public_key.data()) == 0;
}

X25519KeyPair x25519_keypair() {
    X25519KeyPair kp;
    kp.pub.resize(X25519_PK_LEN);
    kp.sec.resize(X25519_SK_LEN);
    crypto_box_keypair(kp.pub.data(), kp.sec.data());
    return kp;
}

ByteVec x25519_shared(const ByteVec& sec, const ByteVec& peer_pub) {
    require_len(sec, X25519_SK_LEN, "X25519 secret key");
    require_len(peer_pub, X25519_PK_LEN, "X25519 peer public key");
    ByteVec shared(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(shared.data(), sec.data(), peer_pub.data()) != 0) {
        throw std::runtime_error("crypto_scalarmult failed: unacceptable peer public key");
    }
    return shared;
}

ByteVec derive_default_key(const std::string& token, const ByteVec& salt_d, const ByteVec& salt_s, const std::string& hwid) {
    require_len(salt_d, SALT_LEN, "salt_d");
    require_len(salt_s, SALT_LEN, "salt_s");
    ByteVec salt = xor_fixed(salt_d, salt_s);
    return hkdf_sha256(str_bytes(token), salt, str_bytes(hwid), KEY_LEN);
}

ByteVec derive_session_key(const ByteVec& Z, const ByteVec& N_d, const ByteVec& N_s, const ByteVec& xid) {
    require_len(N_d, NONCE_LEN, "N_d");
    require_len(N_s, NONCE_LEN, "N_s");
    require_len(xid, HASH32_LEN, "xid");
    ByteVec salt = concat({N_d, N_s});
    return hkdf_sha256(Z, salt, xid, KEY_LEN);
}

ByteVec compute_xid(const std::string& token, const std::string& hwid, const ByteVec& Q_d,
                    const ByteVec& N_d, const ByteVec& H_salt_d, uint64_t T1, const ByteVec& pk1) {
    return hash32_parts({str_bytes(token), str_bytes(hwid), Q_d, N_d, H_salt_d, u64be(T1), pk1});
}

ByteVec compute_mco(const std::string& hwid, const ByteVec& Pub_usr, const ByteVec& pk1, const ByteVec& xid) {
    return hash32_parts({str_bytes(hwid), Pub_usr, pk1, xid});
}

ByteVec build_alpha_msg(const ByteVec& Q_s, const ByteVec& Q_d, const ByteVec& N_s, const ByteVec& N_d,
                        const ByteVec& xid, const ByteVec& salt_s, uint64_t T2,
                        const ByteVec& pk1, const ByteVec& R1,
                        const ByteVec& R, const ByteVec& S2) {
    return concat({Q_s, Q_d, N_s, N_d, xid, salt_s, u64be(T2), pk1, R1, R, S2});
}

ByteVec build_beta_msg(const std::string& hwid, const ByteVec& Pub_usr, const ByteVec& pk1,
                       const ByteVec& Q_d, const ByteVec& Q_s, const ByteVec& N_d, const ByteVec& N_s,
                       const ByteVec& xid, const ByteVec& R, uint64_t T3) {
    return concat({str_bytes(hwid), Pub_usr, pk1, Q_d, Q_s, N_d, N_s, xid, R, u64be(T3)});
}

} // namespace iotproto
