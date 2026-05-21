#include "common.hpp"
#include "mincosig.hpp"
#include "net.hpp"
#include "protocol.hpp"

#include <fstream>
#include <iostream>

using namespace iotproto;
using namespace iotproto::net;

static std::string arg_value(int argc, char** argv, const std::string& name, const std::string& def = "") {
    for (int i = 1; i + 1 < argc; ++i) if (argv[i] == name) return argv[i + 1];
    return def;
}

static bool has_arg(int argc, char** argv, const std::string& name) {
    for (int i = 1; i < argc; ++i) if (argv[i] == name) return true;
    return false;
}

static uint64_t elapsed_since(uint64_t begin_ns) {
    return monotonic_time_ns() - begin_ns;
}

struct ServerPerf {
    uint64_t m1_server_process_ns = 0;
    uint64_t m2_server_generate_ns = 0;
    uint64_t m3_server_process_ns = 0;
    uint64_t m4_server_generate_ns = 0;
};

static void print_server_perf(const ServerPerf& p) {
    std::cout << "\n[Server timing, network send/receive waiting excluded]\n"
              << "Message, server-side operation, time(ms)\n"
              << "M1, process request, " << format_ms(p.m1_server_process_ns) << "\n"
              << "M2, generate response, " << format_ms(p.m2_server_generate_ns) << "\n"
              << "M3, process ownership message, " << format_ms(p.m3_server_process_ns) << "\n"
              << "M4, generate ACK, " << format_ms(p.m4_server_generate_ns) << "\n";
}

static void append_server_perf_csv(const std::string& path, const ServerPerf& p) {
    if (path.empty()) return;
    const bool need_header = !std::ifstream(path).good();
    std::ofstream out(path, std::ios::app);
    if (!out) throw std::runtime_error("cannot open perf csv for append: " + path);
    if (need_header) out << "side,message,operation,time_ms\n";
    out << "server,M1,process_request," << format_ms(p.m1_server_process_ns) << "\n";
    out << "server,M2,generate_response," << format_ms(p.m2_server_generate_ns) << "\n";
    out << "server,M3,process_ownership_message," << format_ms(p.m3_server_process_ns) << "\n";
    out << "server,M4,generate_ack," << format_ms(p.m4_server_generate_ns) << "\n";
}

static void usage() {
    std::cout <<
        "Usage:\n"
        "  ta_server --db ta_db.conf --key ta_key.conf --port 9000 [options]\n\n"
        "Options:\n"
        "  --perf-csv <file>     Append server-side timing results to CSV\n";
}

struct ServerContext {
    std::string db_path;
    std::string perf_csv_path;
    std::map<std::string, std::string> db;
    ByteVec ta_sec;
};

static void handle_client(TcpSocket& sock, ServerContext& ctx) {
    ServerPerf perf;

    Message m1 = recv_message(sock);
    uint64_t t0 = monotonic_time_ns();
    if (m1.type != MSG_M1 || m1.fields.size() != 7) throw std::runtime_error("expected M1 with 7 fields");

    const std::string token = bytes_str(m1.fields[0]);
    const ByteVec Q_d = m1.fields[1];
    const ByteVec N_d = m1.fields[2];
    const ByteVec H_salt_d = m1.fields[3];
    const uint64_t T1 = read_u64be(m1.fields[4]);
    const ByteVec pk1 = m1.fields[5];
    const ByteVec R1 = m1.fields[6];

    require_len(Q_d, X25519_PK_LEN, "Q_d");
    require_len(N_d, NONCE_LEN, "N_d");
    require_len(H_salt_d, HASH32_LEN, "H(salt_d)");
    require_len(m1.fields[4], 8, "T1");
    mincosig::require_valid_point(pk1, "pk1 from M1");
    mincosig::require_valid_point(R1, "R1 from M1");

    if (required_value(ctx.db, "consumed") == "1") throw std::runtime_error("Token already consumed");
    if (hex_encode(str_bytes(token)) != required_value(ctx.db, "token")) throw std::runtime_error("Token mismatch");

    const std::string hwid = required_value(ctx.db, "hwid");
    const ByteVec h_salt_d_db = hex_decode(required_value(ctx.db, "h_salt_d"));
    if (H_salt_d != h_salt_d_db) throw std::runtime_error("H(salt_d) mismatch");

    const ByteVec pub_def = hex_decode(required_value(ctx.db, "pub_def"));
    const ByteVec salt_s = hex_decode(required_value(ctx.db, "salt_s"));
    mincosig::ServerShare server_share;
    server_share.sk2 = hex_decode(required_value(ctx.db, "sk2"));
    server_share.v2 = hex_decode(required_value(ctx.db, "v2"));
    server_share.pk2 = hex_decode(required_value(ctx.db, "pk2"));

    const ByteVec xid = compute_xid(token, hwid, Q_d, N_d, H_salt_d, T1, pk1);
    const ByteVec pub_usr = mincosig::server_compute_pub_usr(server_share, pk1);
    const ByteVec m_co = compute_mco(hwid, pub_usr, pk1, xid);
    perf.m1_server_process_ns = elapsed_since(t0);

    t0 = monotonic_time_ns();
    X25519KeyPair eph = x25519_keypair();
    ByteVec N_s = random_bytes(NONCE_LEN);
    uint64_t T2 = unix_time_seconds();
    ByteVec Z = x25519_shared(eph.sec, Q_d);
    ByteVec session_key = derive_session_key(Z, N_d, N_s, xid);

    mincosig::ServerPartial partial = mincosig::server_partial_sign(server_share, pk1, pub_usr, m_co, R1);

    ByteVec alpha_msg = build_alpha_msg(
        eph.pub, Q_d, N_s, N_d,
        xid, salt_s, T2,
        pk1, R1,
        partial.R, partial.S2
    );

    ByteVec alpha = sign_ed25519(alpha_msg, ctx.ta_sec);

    ByteVec c_salt = aead_encrypt(session_key, concat({salt_s, u64be(T2)}), xid);

    Message m2;
    m2.type = MSG_M2;
    m2.fields = {eph.pub, N_s, u64be(T2), alpha, c_salt, partial.R, partial.S2};
    perf.m2_server_generate_ns = elapsed_since(t0);

    send_message(sock, m2);

    std::cout << "M1 processed; xid=" << hex_encode(xid) << ", waiting for M3...\n";

    Message m3 = recv_message(sock);
    t0 = monotonic_time_ns();
    if (m3.type != MSG_M3 || m3.fields.size() != 2) throw std::runtime_error("expected M3 with 2 fields");
    if (m3.fields[0] != xid) throw std::runtime_error("M3 xid mismatch");

    ByteVec plain3 = aead_decrypt(session_key, m3.fields[1], xid);
    if (plain3.size() != ED25519_SIG_LEN + ED25519_SIG_LEN + 8) {
        throw std::runtime_error("bad M3 plaintext length");
    }
    ByteVec beta(plain3.begin(), plain3.begin() + ED25519_SIG_LEN);
    ByteVec sig_usr(plain3.begin() + ED25519_SIG_LEN, plain3.begin() + ED25519_SIG_LEN + ED25519_SIG_LEN);
    ByteVec T3b(plain3.begin() + ED25519_SIG_LEN + ED25519_SIG_LEN, plain3.end());
    uint64_t T3 = read_u64be(T3b);

    ByteVec beta_msg = build_beta_msg(hwid, pub_usr, pk1, Q_d, eph.pub, N_d, N_s, xid, partial.R, T3);
    if (!verify_ed25519(beta_msg, beta, pub_def)) throw std::runtime_error("beta verification failed");
    if (!mincosig::verify_signature(pub_usr, m_co, sig_usr)) throw std::runtime_error("collaborative EdDSA signature verification failed");

    ctx.db["pub_usr"] = hex_encode(pub_usr);
    ctx.db["consumed"] = "1";
    save_kv_file(ctx.db_path, ctx.db);
    perf.m3_server_process_ns = elapsed_since(t0);

    t0 = monotonic_time_ns();
    uint64_t T4 = unix_time_seconds();
    ByteVec ack = str_bytes("ACK1");
    ByteVec c4 = aead_encrypt(session_key, concat({ack, u64be(T4)}), xid);
    Message m4;
    m4.type = MSG_M4;
    m4.fields = {c4};
    perf.m4_server_generate_ns = elapsed_since(t0);

    send_message(sock, m4);

    std::cout << "Ownership binding success. Pub_usr=" << hex_encode(pub_usr) << "\n";
    print_server_perf(perf);
    append_server_perf_csv(ctx.perf_csv_path, perf);

    sodium_memzero(server_share.sk2.data(), server_share.sk2.size());
    sodium_memzero(server_share.v2.data(), server_share.v2.size());
    sodium_memzero(eph.sec.data(), eph.sec.size());
    sodium_memzero(Z.data(), Z.size());
    sodium_memzero(session_key.data(), session_key.size());
}

int main(int argc, char** argv) {
    try {
        sodium_init_or_throw();
        if (has_arg(argc, argv, "--help")) { usage(); return 0; }
        ServerContext ctx;
        ctx.db_path = arg_value(argc, argv, "--db", "ta_db.conf");
        ctx.perf_csv_path = arg_value(argc, argv, "--perf-csv");
        const std::string key_path = arg_value(argc, argv, "--key", "ta_key.conf");
        const uint16_t port = static_cast<uint16_t>(std::stoi(arg_value(argc, argv, "--port", "9000")));

        ctx.db = load_kv_file(ctx.db_path);
        auto key = load_kv_file(key_path);
        ctx.ta_sec = hex_decode(required_value(key, "ta_sec"));
        require_len(ctx.ta_sec, ED25519_SK_LEN, "ta_sec");

        TcpSocket listener = TcpSocket::listen_on(port);
        std::cout << "TA server listening on port " << port << "...\n";
        while (true) {
            try {
                TcpSocket client = listener.accept_one();
                std::cout << "Client connected.\n";
                handle_client(client, ctx);
                if (ctx.db["consumed"] == "1") {
                    std::cout << "Token consumed; server remains running but will reject reuse.\n";
                }
            } catch (const std::exception& e) {
                std::cerr << "[session] error: " << e.what() << "\n";
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[ta_server] error: " << e.what() << "\n";
        return 1;
    }
}
