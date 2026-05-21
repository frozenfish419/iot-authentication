#include "net.hpp"

#include <cerrno>
#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
using socklen_t = int;
static int last_sock_error() { return WSAGetLastError(); }
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
static int last_sock_error() { return errno; }
#endif

namespace iotproto::net {

static uint32_t read_u32be_raw(const unsigned char* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

static void write_u32be_raw(unsigned char* p, uint32_t x) {
    p[0] = static_cast<unsigned char>((x >> 24) & 0xff);
    p[1] = static_cast<unsigned char>((x >> 16) & 0xff);
    p[2] = static_cast<unsigned char>((x >> 8) & 0xff);
    p[3] = static_cast<unsigned char>(x & 0xff);
}

TcpSocket::TcpSocket() = default;
TcpSocket::TcpSocket(std::intptr_t fd) : fd_(fd) {}

TcpSocket::TcpSocket(TcpSocket&& other) noexcept : fd_(other.fd_) {
    other.fd_ = -1;
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

TcpSocket::~TcpSocket() { close(); }

void TcpSocket::platform_init() {
#ifdef _WIN32
    static bool done = false;
    if (!done) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
        done = true;
    }
#endif
}

bool TcpSocket::valid() const { return fd_ >= 0; }

void TcpSocket::close() {
    if (fd_ >= 0) {
#ifdef _WIN32
        closesocket(static_cast<SOCKET>(fd_));
#else
        ::close(fd_);
#endif
        fd_ = -1;
    }
}

TcpSocket TcpSocket::connect_to(const std::string& host, uint16_t port) {
    platform_init();
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    std::string port_s = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res) != 0) {
        throw std::runtime_error("getaddrinfo failed for " + host);
    }
    std::intptr_t fd = -1;
    for (addrinfo* p = res; p; p = p->ai_next) {
        fd = static_cast<std::intptr_t>(socket(p->ai_family, p->ai_socktype, p->ai_protocol));
        if (fd < 0) continue;
        if (::connect(fd, p->ai_addr, static_cast<socklen_t>(p->ai_addrlen)) == 0) {
            freeaddrinfo(res);
            return TcpSocket(fd);
        }
#ifdef _WIN32
        closesocket(static_cast<SOCKET>(fd));
#else
        ::close(fd);
#endif
        fd = -1;
    }
    freeaddrinfo(res);
    throw std::runtime_error("connect failed, error=" + std::to_string(last_sock_error()));
}

TcpSocket TcpSocket::listen_on(uint16_t port, int backlog) {
    platform_init();
    std::intptr_t fd = static_cast<std::intptr_t>(socket(AF_INET, SOCK_STREAM, 0));
    if (fd < 0) throw std::runtime_error("socket failed");
    int opt = 1;
#ifdef _WIN32
    setsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
#ifdef _WIN32
        closesocket(static_cast<SOCKET>(fd));
#else
        ::close(fd);
#endif
        throw std::runtime_error("bind failed, error=" + std::to_string(last_sock_error()));
    }
    if (listen(fd, backlog) != 0) {
#ifdef _WIN32
        closesocket(static_cast<SOCKET>(fd));
#else
        ::close(fd);
#endif
        throw std::runtime_error("listen failed");
    }
    return TcpSocket(fd);
}

TcpSocket TcpSocket::accept_one() {
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    std::intptr_t cfd = static_cast<std::intptr_t>(accept(fd_, reinterpret_cast<sockaddr*>(&addr), &len));
    if (cfd < 0) throw std::runtime_error("accept failed");
    return TcpSocket(cfd);
}

void TcpSocket::send_all(const unsigned char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
#ifdef _WIN32
        int n = send(static_cast<SOCKET>(fd_), reinterpret_cast<const char*>(data + sent), static_cast<int>(len - sent), 0);
#else
        ssize_t n = send(fd_, data + sent, len - sent, 0);
#endif
        if (n <= 0) throw std::runtime_error("send failed");
        sent += static_cast<size_t>(n);
    }
}

void TcpSocket::recv_all(unsigned char* data, size_t len) {
    size_t got = 0;
    while (got < len) {
#ifdef _WIN32
        int n = recv(static_cast<SOCKET>(fd_), reinterpret_cast<char*>(data + got), static_cast<int>(len - got), 0);
#else
        ssize_t n = recv(fd_, data + got, len - got, 0);
#endif
        if (n <= 0) throw std::runtime_error("recv failed or peer closed");
        got += static_cast<size_t>(n);
    }
}

void send_message(TcpSocket& sock, const Message& msg) {
    ByteVec body;
    body.push_back(msg.type);
    body.push_back(static_cast<unsigned char>(msg.fields.size()));
    body.push_back(0); body.push_back(0); // reserved
    for (const auto& f : msg.fields) {
        if (f.size() > 10 * 1024 * 1024) throw std::runtime_error("field too large");
        unsigned char lenbuf[4];
        write_u32be_raw(lenbuf, static_cast<uint32_t>(f.size()));
        body.insert(body.end(), lenbuf, lenbuf + 4);
        body.insert(body.end(), f.begin(), f.end());
    }
    unsigned char hdr[8] = {'I','O','B','C',0,0,0,0};
    write_u32be_raw(hdr + 4, static_cast<uint32_t>(body.size()));
    sock.send_all(hdr, sizeof(hdr));
    sock.send_all(body.data(), body.size());
}

Message recv_message(TcpSocket& sock) {
    unsigned char hdr[8];
    sock.recv_all(hdr, sizeof(hdr));
    if (hdr[0] != 'I' || hdr[1] != 'O' || hdr[2] != 'B' || hdr[3] != 'C') {
        throw std::runtime_error("bad message magic");
    }
    uint32_t body_len = read_u32be_raw(hdr + 4);
    if (body_len < 4 || body_len > 10 * 1024 * 1024) throw std::runtime_error("bad message length");
    ByteVec body(body_len);
    sock.recv_all(body.data(), body.size());
    Message msg;
    msg.type = body[0];
    uint8_t count = body[1];
    size_t off = 4;
    for (uint8_t i = 0; i < count; ++i) {
        if (off + 4 > body.size()) throw std::runtime_error("bad field header");
        uint32_t len = read_u32be_raw(body.data() + off);
        off += 4;
        if (off + len > body.size()) throw std::runtime_error("bad field length");
        msg.fields.emplace_back(body.begin() + off, body.begin() + off + len);
        off += len;
    }
    if (off != body.size()) throw std::runtime_error("trailing bytes in message");
    return msg;
}

} // namespace iotproto::net
