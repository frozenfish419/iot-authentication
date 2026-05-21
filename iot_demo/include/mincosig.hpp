#pragma once

#include "common.hpp"

namespace iotproto::mincosig {

struct DeviceShare {
    ByteVec sk1;      // 32-byte Ed25519 scalar
    ByteVec v1;       // 32-byte nonce seed
    ByteVec pk1;      // 32-byte Ed25519 point
    ByteVec pub_usr;  // 32-byte Ed25519 public key
};

struct ServerShare {
    ByteVec sk2;      // 32-byte Ed25519 scalar
    ByteVec v2;       // 32-byte nonce seed
    ByteVec pk2;      // 32-byte Ed25519 point
};

struct DeviceSignState {
    ByteVec r1;       // local nonce scalar; never send
    ByteVec R1;       // send to server
};

struct ServerPartial {
    ByteVec R;        // final nonce point
    ByteVec S2;       // server signing component scalar
};

DeviceShare create_device_share_from_pk2(const ByteVec& pk2);
ServerShare create_server_share_random();
ByteVec server_compute_pub_usr(const ServerShare& s, const ByteVec& pk1);

DeviceSignState device_begin_sign(const DeviceShare& d, const ByteVec& m_co);
ServerPartial server_partial_sign(const ServerShare& s, const ByteVec& pk1, const ByteVec& pub_usr,
                                  const ByteVec& m_co, const ByteVec& R1);
ByteVec device_finish_signature(const DeviceShare& d, const DeviceSignState& st, const ServerPartial& partial);
bool verify_signature(const ByteVec& pub_usr, const ByteVec& m_co, const ByteVec& signature);

void require_valid_point(const ByteVec& p, const std::string& name);
void require_scalar(const ByteVec& s, const std::string& name);
ByteVec hash_to_scalar_sha512(const std::vector<ByteVec>& parts);

} // namespace iotproto::mincosig
