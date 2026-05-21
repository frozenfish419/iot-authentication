#pragma once

#include "common.hpp"

namespace iotproto {

constexpr uint8_t MSG_M1 = 1;
constexpr uint8_t MSG_M2 = 2;
constexpr uint8_t MSG_M3 = 3;
constexpr uint8_t MSG_M4 = 4;

struct DefaultKeyPair {
    ByteVec pub; // 32
    ByteVec sec; // 64
};

DefaultKeyPair ed25519_keypair();
ByteVec sign_ed25519(const ByteVec& message, const ByteVec& secret_key);
bool verify_ed25519(const ByteVec& message, const ByteVec& sig, const ByteVec& public_key);

struct X25519KeyPair {
    ByteVec pub; // 32
    ByteVec sec; // 32
};

X25519KeyPair x25519_keypair();
ByteVec x25519_shared(const ByteVec& sec, const ByteVec& peer_pub);

ByteVec derive_default_key(const std::string& token, const ByteVec& salt_d, const ByteVec& salt_s, const std::string& hwid);
ByteVec derive_session_key(const ByteVec& Z, const ByteVec& N_d, const ByteVec& N_s, const ByteVec& xid);
ByteVec compute_xid(const std::string& token, const std::string& hwid, const ByteVec& Q_d,
                    const ByteVec& N_d, const ByteVec& H_salt_d, uint64_t T1, const ByteVec& pk1);
ByteVec compute_mco(const std::string& hwid, const ByteVec& Pub_usr, const ByteVec& pk1, const ByteVec& xid);
ByteVec build_alpha_msg(const ByteVec& Q_s, const ByteVec& Q_d, const ByteVec& N_s, const ByteVec& N_d,
                        const ByteVec& xid, const ByteVec& salt_s, uint64_t T2,
                        const ByteVec& pk1, const ByteVec& R1,
                        const ByteVec& R, const ByteVec& S2);
ByteVec build_beta_msg(const std::string& hwid, const ByteVec& Pub_usr, const ByteVec& pk1,
                       const ByteVec& Q_d, const ByteVec& Q_s, const ByteVec& N_d, const ByteVec& N_s,
                       const ByteVec& xid, const ByteVec& R, uint64_t T3);

void require_len(const ByteVec& v, size_t n, const std::string& name);

} // namespace iotproto
