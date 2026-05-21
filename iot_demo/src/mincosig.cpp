#include "mincosig.hpp"

namespace iotproto::mincosig {

void require_valid_point(const ByteVec& p, const std::string& name) {
    if (p.size() != ED25519_POINT_LEN || crypto_core_ed25519_is_valid_point(p.data()) != 1) {
        throw std::runtime_error("invalid Ed25519 point: " + name);
    }
}

void require_scalar(const ByteVec& s, const std::string& name) {
    if (s.size() != ED25519_SCALAR_LEN) {
        throw std::runtime_error("invalid Ed25519 scalar length: " + name);
    }
}

ByteVec hash_to_scalar_sha512(const std::vector<ByteVec>& parts) {
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    for (const auto& p : parts) {
        crypto_hash_sha512_update(&st, p.data(), p.size());
    }
    ByteVec h(crypto_hash_sha512_BYTES);
    crypto_hash_sha512_final(&st, h.data());
    ByteVec r(ED25519_SCALAR_LEN);
    crypto_core_ed25519_scalar_reduce(r.data(), h.data());
    sodium_memzero(h.data(), h.size());
    return r;
}

static ByteVec random_scalar() {
    ByteVec s(ED25519_SCALAR_LEN);
    crypto_core_ed25519_scalar_random(s.data());
    return s;
}

static ByteVec scalar_base_mul(const ByteVec& s) {
    require_scalar(s, "scalar_base_mul");
    ByteVec q(ED25519_POINT_LEN);
    if (crypto_scalarmult_ed25519_base_noclamp(q.data(), s.data()) != 0) {
        throw std::runtime_error("crypto_scalarmult_ed25519_base_noclamp failed");
    }
    require_valid_point(q, "scalar_base_mul output");
    return q;
}

static ByteVec scalar_point_mul(const ByteVec& s, const ByteVec& p, const std::string& name) {
    require_scalar(s, name + " scalar");
    require_valid_point(p, name + " point");
    ByteVec q(ED25519_POINT_LEN);
    if (crypto_scalarmult_ed25519_noclamp(q.data(), s.data(), p.data()) != 0) {
        throw std::runtime_error("crypto_scalarmult_ed25519_noclamp failed: " + name);
    }
    require_valid_point(q, name + " output");
    return q;
}

DeviceShare create_device_share_from_pk2(const ByteVec& pk2) {
    require_valid_point(pk2, "pk2");
    DeviceShare d;
    d.sk1 = random_scalar();
    d.v1 = random_bytes(32);
    d.pk1 = scalar_base_mul(d.sk1);
    d.pub_usr = scalar_point_mul(d.sk1, pk2, "Pub_usr = sk1*pk2");
    return d;
}

ServerShare create_server_share_random() {
    ServerShare s;
    s.sk2 = random_scalar();
    s.v2 = random_bytes(32);
    s.pk2 = scalar_base_mul(s.sk2);
    return s;
}

ByteVec server_compute_pub_usr(const ServerShare& s, const ByteVec& pk1) {
    return scalar_point_mul(s.sk2, pk1, "Pub_usr = sk2*pk1");
}

DeviceSignState device_begin_sign(const DeviceShare& d, const ByteVec& m_co) {
    DeviceSignState st;
    st.r1 = hash_to_scalar_sha512({d.v1, m_co});
    st.R1 = scalar_base_mul(st.r1);
    return st;
}

ServerPartial server_partial_sign(const ServerShare& s, const ByteVec& pk1, const ByteVec& pub_usr,
                                  const ByteVec& m_co, const ByteVec& R1) {
    require_valid_point(pk1, "pk1");
    require_valid_point(pub_usr, "Pub_usr");
    require_valid_point(R1, "R1");

    ByteVec r2 = hash_to_scalar_sha512({s.v2, m_co, R1});
    ByteVec r2pk1 = scalar_point_mul(r2, pk1, "r2*pk1");

    ByteVec R(ED25519_POINT_LEN);
    if (crypto_core_ed25519_add(R.data(), R1.data(), r2pk1.data()) != 0) {
        throw std::runtime_error("crypto_core_ed25519_add failed for R");
    }
    require_valid_point(R, "R");

    ByteVec h = hash_to_scalar_sha512({R, pub_usr, m_co});
    ByteVec hd2(ED25519_SCALAR_LEN);
    crypto_core_ed25519_scalar_mul(hd2.data(), h.data(), s.sk2.data());

    ByteVec S2(ED25519_SCALAR_LEN);
    crypto_core_ed25519_scalar_add(S2.data(), r2.data(), hd2.data());

    sodium_memzero(r2.data(), r2.size());
    sodium_memzero(h.data(), h.size());
    sodium_memzero(hd2.data(), hd2.size());

    return ServerPartial{R, S2};
}

ByteVec device_finish_signature(const DeviceShare& d, const DeviceSignState& st, const ServerPartial& partial) {
    require_valid_point(partial.R, "R");
    require_scalar(partial.S2, "S2");
    ByteVec d1S2(ED25519_SCALAR_LEN);
    crypto_core_ed25519_scalar_mul(d1S2.data(), d.sk1.data(), partial.S2.data());
    ByteVec S(ED25519_SCALAR_LEN);
    crypto_core_ed25519_scalar_add(S.data(), st.r1.data(), d1S2.data());
    ByteVec sig;
    sig.reserve(ED25519_SIG_LEN);
    sig.insert(sig.end(), partial.R.begin(), partial.R.end());
    sig.insert(sig.end(), S.begin(), S.end());
    sodium_memzero(d1S2.data(), d1S2.size());
    sodium_memzero(S.data(), S.size());
    return sig;
}

bool verify_signature(const ByteVec& pub_usr, const ByteVec& m_co, const ByteVec& signature) {
    if (pub_usr.size() != ED25519_PK_LEN || signature.size() != ED25519_SIG_LEN) return false;
    return crypto_sign_verify_detached(signature.data(), m_co.data(), m_co.size(), pub_usr.data()) == 0;
}

} // namespace iotproto::mincosig
