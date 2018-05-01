#include <errno.h>
#include "net/internal/socket/socket.h"

#define IOV_MAX 1024

namespace net {
  namespace internal {
    namespace socket {
      static inline bool make_non_blocking(SOCKET sock)
      {
        // Make socket non-blocking.
        u_long arg = 1;
        return (ioctlsocket(sock, FIONBIO, &arg) == 0);
      }

      handle_t create(int domain, int type, int protocol)
      {
        // Create socket.
        SOCKET sock;
        if ((sock = WSASocket(domain,
                              type,
                              protocol,
                              nullptr,
                              0,
                              0)) != INVALID_SOCKET) {
          // Make socket non-blocking.
          if (make_non_blocking(sock)) {
            return sock;
          }

          socket::close(sock);
        }

        return invalid_handle;
      }

      bool close(handle_t sock)
      {
        return (::closesocket(sock) == 0);
      }

      bool shutdown(handle_t sock, int how)
      {
        return (::shutdown(sock, how) == 0);
      }

      bool connect(handle_t sock,
                   const struct sockaddr* addr,
                   socklen_t addrlen)
      {
        int ret;
        while (((ret = WSAConnect(sock,
                                  addr,
                                  addrlen,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr)) == SOCKET_ERROR) &&
               (WSAGetLastError() == WSAEINTR));

        return ((ret == 0) || (WSAGetLastError() == WSAEWOULDBLOCK));
      }

      bool connect(handle_t sock,
                   const struct sockaddr* addr,
                   socklen_t addrlen,
                   int timeout)
      {
        int ret;
        while (((ret = WSAConnect(sock,
                                  addr,
                                  addrlen,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr)) == SOCKET_ERROR) &&
               (WSAGetLastError() == WSAEINTR));

        if ((ret == 0) ||
            ((WSAGetLastError() == WSAEWOULDBLOCK) &&
             (wait_writable(sock, timeout)))) {
          int error;
          return ((get_socket_error(sock, error)) && (error == 0));
        } else {
          return false;
        }
      }

      handle_t connect(const struct sockaddr* addr, socklen_t addrlen)
      {
        handle_t sock;
        if ((sock = create(addr->sa_family, SOCK_STREAM)) != invalid_handle) {
          if (socket::connect(sock, addr, addrlen)) {
            return sock;
          }

          socket::close(sock);
        }

        return invalid_handle;
      }

      handle_t connect(const struct sockaddr* addr,
                       socklen_t addrlen,
                       int timeout)
      {
        handle_t sock;
        if ((sock = create(addr->sa_family, SOCK_STREAM)) != invalid_handle) {
          if (socket::connect(sock, addr, addrlen, timeout)) {
            return sock;
          }

          socket::close(sock);
        }

        return invalid_handle;
      }

      bool get_socket_error(handle_t sock, int& error)
      {
        socklen_t optlen = sizeof(int);
        return (::getsockopt(sock,
                             SOL_SOCKET,
                             SO_ERROR,
                             reinterpret_cast<char*>(&error),
                             &optlen) == 0);
      }

      bool get_recvbuf_size(handle_t sock, int& size)
      {
        socklen_t optlen = sizeof(int);
        return (::getsockopt(sock,
                             SOL_SOCKET,
                             SO_RCVBUF,
                             reinterpret_cast<char*>(&size),
                             &optlen) == 0);
      }

      bool set_recvbuf_size(handle_t sock, int size)
      {
        return (::setsockopt(sock,
                             SOL_SOCKET,
                             SO_RCVBUF,
                             reinterpret_cast<const char*>(&size),
                             sizeof(int)) == 0);
      }

      bool get_sendbuf_size(handle_t sock, int& size)
      {
        socklen_t optlen = sizeof(int);
        return (::getsockopt(sock,
                             SOL_SOCKET,
                             SO_SNDBUF,
                             reinterpret_cast<char*>(&size),
                             &optlen) == 0);
      }

      bool set_sendbuf_size(handle_t sock, int size)
      {
        return (::setsockopt(sock,
                             SOL_SOCKET,
                             SO_SNDBUF,
                             reinterpret_cast<const char*>(&size),
                             sizeof(int)) == 0);
      }

      bool get_keep_alive(handle_t sock, bool& on)
      {
        BOOL optval;
        socklen_t optlen = sizeof(BOOL);

        if (::getsockopt(sock,
                         SOL_SOCKET,
                         SO_KEEPALIVE,
                         reinterpret_cast<char*>(&optval),
                         &optlen) == 0) {
          on = (optval != 0);

          return true;
        }

        return false;
      }

      bool set_keep_alive(handle_t sock, bool on)
      {
        BOOL optval = on;
        return (::setsockopt(sock,
                             SOL_SOCKET,
                             SO_KEEPALIVE,
                             reinterpret_cast<const char*>(&optval),
                             sizeof(BOOL)) == 0);
      }

      bool get_tcp_no_delay(handle_t sock, bool& on)
      {
        BOOL optval;
        socklen_t optlen = sizeof(BOOL);

        if (::getsockopt(sock,
                         IPPROTO_TCP,
                         TCP_NODELAY,
                         reinterpret_cast<char*>(&optval),
                         &optlen) == 0) {
          on = (optval != 0);

          return true;
        }

        return false;
      }

      bool set_tcp_no_delay(handle_t sock, bool on)
      {
        BOOL optval = on;
        return (::setsockopt(sock,
                             IPPROTO_TCP,
                             TCP_NODELAY,
                             reinterpret_cast<const char*>(&optval),
                             sizeof(BOOL)) == 0);
      }

      bool bind(handle_t sock, const struct sockaddr* addr, socklen_t addrlen)
      {
        // Reuse address.
        BOOL optval = 1;
        return ((::setsockopt(sock,
                              SOL_SOCKET,
                              SO_REUSEADDR,
                              reinterpret_cast<const char*>(&optval),
                              sizeof(BOOL)) == 0) &&
                (::bind(sock, addr, addrlen) == 0));
      }

      bool listen(handle_t sock)
      {
        return (::listen(sock, SOMAXCONN) == 0);
      }

      handle_t listen(const struct sockaddr* addr, socklen_t addrlen)
      {
        handle_t sock;
        if ((sock = create(addr->sa_family, SOCK_STREAM)) != invalid_handle) {
          if ((socket::bind(sock, addr, addrlen)) && (socket::listen(sock))) {
            return sock;
          }

          socket::close(sock);
        }

        return invalid_handle;
      }

      handle_t accept(handle_t sock, struct sockaddr* addr, socklen_t* addrlen)
      {
        handle_t s;
        while (((s = WSAAccept(sock,
                               addr,
                               addrlen,
                               nullptr,
                               0)) == INVALID_SOCKET) &&
               (WSAGetLastError() == WSAEINTR));

        if (s != invalid_handle) {
          if (make_non_blocking(s)) {
            return s;
          }

          socket::close(s);
        }

        return invalid_handle;
      }

      handle_t accept(handle_t sock,
                      struct sockaddr* addr,
                      socklen_t* addrlen,
                      int timeout)
      {
        handle_t s;
        if ((s = socket::accept(sock, addr, addrlen)) != invalid_handle) {
          return s;
        } else if ((WSAGetLastError() == WSAEWOULDBLOCK) &&
                   (wait_readable(sock, timeout))) {
          return socket::accept(sock, addr, addrlen);
        } else {
          return invalid_handle;
        }
      }

      ssize_t recv(handle_t sock, void* buf, size_t len, DWORD flags)
      {
        WSABUF wsabuf{len, static_cast<char*>(buf)};
        DWORD received;
        int ret;
        while (((ret = WSARecv(sock,
                               &wsabuf,
                               1,
                               &received,
                               &flags,
                               nullptr,
                               nullptr)) == SOCKET_ERROR) &&
               (WSAGetLastError() == WSAEINTR));

        return (ret == 0) ? received : -1;
      }

      ssize_t recv(handle_t sock,
                   void* buf,
                   size_t len,
                   DWORD flags,
                   int timeout)
      {
        ssize_t ret;
        if ((ret = socket::recv(sock, buf, len, flags)) != -1) {
          return ret;
        } else if ((WSAGetLastError() == WSAEWOULDBLOCK) &&
                   (wait_readable(sock, timeout))) {
          return socket::recv(sock, buf, len, flags);
        } else {
          return -1;
        }
      }

      ssize_t send(handle_t sock, const void* buf, size_t len, DWORD flags)
      {
        WSABUF wsabuf{len, static_cast<char*>(const_cast<void*>(buf))};
        DWORD sent;
        int ret;
        while (((ret = WSASend(sock,
                               &wsabuf,
                               1,
                               &sent,
                               flags,
                               nullptr,
                               nullptr)) == SOCKET_ERROR) &&
               (WSAGetLastError() == WSAEINTR));

        return (ret == 0) ? sent : -1;
      }

      bool send(handle_t sock,
                const void* buf,
                size_t len,
                DWORD flags,
                int timeout)
      {
        const uint8_t* b = reinterpret_cast<const uint8_t*>(buf);

        do {
          ssize_t ret;
          if ((ret = socket::send(sock, b, len, flags)) >= 0) {
            if ((len -= ret) == 0) {
              return true;
            }

            if (wait_writable(sock, timeout)) {
              b += ret;
            } else {
              return false;
            }
          } else {
            if ((WSAGetLastError() != WSAEWOULDBLOCK) ||
                (!wait_writable(sock, timeout))) {
              return false;
            }
          }
        } while (true);
      }

      ssize_t readv(handle_t sock, const struct iovec* iov, unsigned iovcnt)
      {
        DWORD received;
        int ret;
        while (((ret = WSARecv(sock,
                               reinterpret_cast<LPWSABUF>(
                                 const_cast<struct iovec*>(iov)
                               ),
                               iovcnt,
                               &received,
                               nullptr,
                               nullptr,
                               nullptr)) == SOCKET_ERROR) &&
               (WSAGetLastError() == WSAEINTR));

        return (ret == 0) ? received : -1;
      }

      ssize_t readv(handle_t sock,
                    const struct iovec* iov,
                    unsigned iovcnt,
                    int timeout)
      {
        ssize_t ret;
        if ((ret = socket::readv(sock, iov, iovcnt)) != -1) {
          return ret;
        } else if ((WSAGetLastError() == WSAEWOULDBLOCK) &&
                   (wait_readable(sock, timeout))) {
          return socket::readv(sock, iov, iovcnt);
        } else {
          return -1;
        }
      }

      ssize_t writev(handle_t sock, const struct iovec* iov, unsigned iovcnt)
      {
        DWORD sent;
        int ret;
        while (((ret = WSASend(sock,
                               reinterpret_cast<LPWSABUF>(
                                 const_cast<struct iovec*>(iov)
                               ),
                               iovcnt,
                               &sent,
                               0,
                               nullptr,
                               nullptr)) == SOCKET_ERROR) &&
               (WSAGetLastError() == WSAEINTR));

        return (ret == 0) ? sent : -1;
      }

      bool writev(handle_t sock,
                  const struct iovec* iov,
                  unsigned iovcnt,
                  int timeout)
      {
        if (iovcnt <= IOV_MAX) {
          struct iovec vec[IOV_MAX];
          size_t total = 0;

          for (unsigned i = 0; i < iovcnt; i++) {
            vec[i] = iov[i];

            total += vec[i].iov_len;
          }

          struct iovec* v = vec;
          size_t sent = 0;

          do {
            ssize_t ret;
            if ((ret = socket::writev(sock, v, iovcnt)) >= 0) {
              if ((sent += ret) == total) {
                return true;
              }

              if (wait_writable(sock, timeout)) {
                while (static_cast<size_t>(ret) >= v->iov_len) {
                  ret -= v->iov_len;

                  v++;
                  iovcnt--;
                }

                if (ret > 0) {
                  v->iov_base += ret;
                  v->iov_len -= ret;
                }
              } else {
                return false;
              }
            } else {
              if ((WSAGetLastError() != WSAEWOULDBLOCK) ||
                  (!wait_writable(sock, timeout))) {
                return false;
              }
            }
          } while (true);
        } else {
          errno = EINVAL;
          return false;
        }
      }

      ssize_t recvfrom(handle_t sock,
                       void* buf,
                       size_t len,
                       struct sockaddr* addr,
                       socklen_t* addrlen,
                       DWORD flags)
      {
        WSABUF wsabuf{len, static_cast<char*>(buf)};
        DWORD received;
        int ret;
        while (((ret = WSARecvFrom(sock,
                                   &wsabuf,
                                   1,
                                   &received,
                                   &flags,
                                   addr,
                                   addrlen,
                                   nullptr,
                                   nullptr)) == SOCKET_ERROR) &&
               (WSAGetLastError() == WSAEINTR));

        return (ret == 0) ? received : -1;
      }

      ssize_t recvfrom(handle_t sock,
                       void* buf,
                       size_t len,
                       struct sockaddr* addr,
                       socklen_t* addrlen,
                       DWORD flags,
                       int timeout)
      {
        ssize_t ret;
        if ((ret = socket::recvfrom(sock,
                                    buf,
                                    len,
                                    addr,
                                    addrlen,
                                    flags)) != -1) {
          return ret;
        } else if ((WSAGetLastError() == WSAEWOULDBLOCK) &&
                   (wait_readable(sock, timeout))) {
          return socket::recvfrom(sock, buf, len, addr, addrlen, flags);
        } else {
          return -1;
        }
      }

      ssize_t sendto(handle_t sock,
                     const void* buf,
                     size_t len,
                     const struct sockaddr* addr,
                     socklen_t addrlen,
                     DWORD flags)
      {
        WSABUF wsabuf{len, static_cast<char*>(const_cast<void*>(buf))};
        DWORD sent;
        int ret;
        while (((ret = WSASendTo(sock,
                                 &wsabuf,
                                 1,
                                 &sent,
                                 flags,
                                 addr,
                                 addrlen,
                                 nullptr,
                                 nullptr)) == SOCKET_ERROR) &&
               (WSAGetLastError() == WSAEINTR));

        return (ret == 0) ? sent : -1;
      }

      bool sendto(handle_t sock,
                  const void* buf,
                  size_t len,
                  const struct sockaddr* addr,
                  socklen_t addrlen,
                  DWORD flags,
                  int timeout)
      {
        const uint8_t* b = reinterpret_cast<const uint8_t*>(buf);

        do {
          ssize_t ret;
          if ((ret = socket::sendto(sock,
                                    b,
                                    len,
                                    addr,
                                    addrlen,
                                    flags)) >= 0) {
            if ((len -= ret) == 0) {
              return true;
            }

            if (wait_writable(sock, timeout)) {
              b += ret;
            } else {
              return false;
            }
          } else {
            if ((WSAGetLastError() != WSAEWOULDBLOCK) ||
                (!wait_writable(sock, timeout))) {
              return false;
            }
          }
        } while (true);
      }

#if HAVE_RECVMSG
      ssize_t recvmsg(handle_t sock, struct msghdr* msg)
      {
        DWORD received;
        int ret;
        while (((ret = WSARecvMsg(sock,
                                  reinterpret_cast<LPWSAMSG>(msg),
                                  &received,
                                  nullptr,
                                  nullptr)) == SOCKET_ERROR) &&
               (WSAGetLastError() == WSAEINTR));

        return (ret == 0) ? received : -1;
      }

      ssize_t recvmsg(handle_t sock, struct msghdr* msg, int timeout)
      {
        ssize_t ret;
        if ((ret = socket::recvmsg(sock, msg)) != -1) {
          return ret;
        } else if ((WSAGetLastError() == WSAEWOULDBLOCK) &&
                   (wait_readable(sock, timeout))) {
          return socket::recvmsg(sock, msg);
        } else {
          return -1;
        }
      }
#endif // HAVE_RECVMSG

      ssize_t sendmsg(handle_t sock, const struct msghdr* msg, DWORD flags)
      {
        DWORD sent;
        int ret;
        while (((ret = WSASendMsg(sock,
                                  reinterpret_cast<LPWSAMSG>(
                                    const_cast<struct msghdr*>(msg)
                                  ),
                                  flags,
                                  &sent,
                                  nullptr,
                                  nullptr)) == SOCKET_ERROR) &&
               (WSAGetLastError() == WSAEINTR));

        return (ret == 0) ? sent : -1;
      }

      bool sendmsg(handle_t sock,
                   const struct msghdr* msg,
                   DWORD flags,
                   int timeout)
      {
        size_t iovcnt;
        if ((iovcnt = msg->msg_iovlen) <= IOV_MAX) {
          struct msghdr m = *msg;

          struct iovec vec[IOV_MAX];
          size_t total = 0;

          for (size_t i = 0; i < iovcnt; i++) {
            vec[i] = *reinterpret_cast<const struct iovec*>(msg->msg_iov + i);

            total += vec[i].iov_len;
          }

          m.msg_iov = reinterpret_cast<LPWSABUF>(vec);
          size_t sent = 0;

          do {
            ssize_t ret;
            if ((ret = socket::sendmsg(sock, msg, flags)) >= 0) {
              if ((sent += ret) == total) {
                return true;
              }

              if (wait_writable(sock, timeout)) {
                while (static_cast<size_t>(ret) >= m.msg_iov->len) {
                  ret -= m.msg_iov->len;

                  m.msg_iov++;
                  m.msg_iovlen--;
                }

                if (ret > 0) {
                  m.msg_iov->buf += ret;
                  m.msg_iov->len -= ret;
                }
              } else {
                return false;
              }
            } else {
              if ((WSAGetLastError() != WSAEWOULDBLOCK) ||
                  (!wait_writable(sock, timeout))) {
                return false;
              }
            }
          } while (true);
        } else {
          errno = EINVAL;
          return false;
        }
      }

      bool wait_readable(handle_t sock, int timeout)
      {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);

        struct timeval tv{timeout / 1000, (timeout % 1000) * 1000};

        return (select(0, &rfds, nullptr, nullptr, &tv) == 1);
      }

      bool wait_writable(handle_t sock, int timeout)
      {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);

        struct timeval tv{timeout / 1000, (timeout % 1000) * 1000};

        return (select(0, nullptr, &wfds, nullptr, &tv) == 1);
      }
    }
  }
}
