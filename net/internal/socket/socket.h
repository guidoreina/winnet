#ifndef NET_INTERNAL_SOCKET_H
#define NET_INTERNAL_SOCKET_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include "sys/uio.h"
#include "sys/types.h"

namespace net {
  namespace internal {
    namespace socket {
      typedef SOCKET handle_t;
      static const handle_t invalid_handle = INVALID_SOCKET;

      // Create socket.
      handle_t create(int domain, int type, int protocol = 0);

      // Close socket.
      bool close(handle_t sock);

      // Shutdown socket.
      bool shutdown(handle_t sock, int how);

      // Connect.
      bool connect(handle_t sock,
                   const struct sockaddr* addr,
                   socklen_t addrlen);

      bool connect(handle_t sock,
                   const struct sockaddr* addr,
                   socklen_t addrlen,
                   int timeout);

      handle_t connect(const struct sockaddr* addr, socklen_t addrlen);
      handle_t connect(const struct sockaddr* addr,
                       socklen_t addrlen,
                       int timeout);

      // Get socket error.
      bool get_socket_error(handle_t sock, int& error);

      // Get receive buffer size.
      bool get_recvbuf_size(handle_t sock, int& size);

      // Set receive buffer size.
      bool set_recvbuf_size(handle_t sock, int size);

      // Get send buffer size.
      bool get_sendbuf_size(handle_t sock, int& size);

      // Set send buffer size.
      bool set_sendbuf_size(handle_t sock, int size);

      // Get keep-alive.
      bool get_keep_alive(handle_t sock, bool& on);

      // Set keep-alive.
      bool set_keep_alive(handle_t sock, bool on);

      // Get TCP no delay.
      bool get_tcp_no_delay(handle_t sock, bool& on);

      // Set TCP no delay.
      bool set_tcp_no_delay(handle_t sock, bool on);

      // Bind.
      bool bind(handle_t sock, const struct sockaddr* addr, socklen_t addrlen);

      // Listen.
      bool listen(handle_t sock);
      handle_t listen(const struct sockaddr* addr, socklen_t addrlen);

      // Accept.
      handle_t accept(handle_t sock, struct sockaddr* addr, socklen_t* addrlen);
      handle_t accept(handle_t sock,
                      struct sockaddr* addr,
                      socklen_t* addrlen,
                      int timeout);

      static inline handle_t accept(handle_t sock)
      {
        return socket::accept(sock, nullptr, nullptr);
      }

      static inline handle_t accept(handle_t sock, int timeout)
      {
        return socket::accept(sock, nullptr, nullptr, timeout);
      }

      // Receive.
      ssize_t recv(handle_t sock, void* buf, size_t len, DWORD flags = 0);
      ssize_t recv(handle_t sock,
                   void* buf,
                   size_t len,
                   DWORD flags,
                   int timeout);

      // Send.
      ssize_t send(handle_t sock, const void* buf, size_t len, DWORD flags = 0);
      bool send(handle_t sock,
                const void* buf,
                size_t len,
                DWORD flags,
                int timeout);

      // Read into multiple buffers.
      ssize_t readv(handle_t sock, const struct iovec* iov, unsigned iovcnt);
      ssize_t readv(handle_t sock,
                    const struct iovec* iov,
                    unsigned iovcnt,
                    int timeout);

      // Write from multiple buffers.
      ssize_t writev(handle_t sock, const struct iovec* iov, unsigned iovcnt);
      bool writev(handle_t sock,
                  const struct iovec* iov,
                  unsigned iovcnt,
                  int timeout);

      // Receive from.
      ssize_t recvfrom(handle_t sock,
                       void* buf,
                       size_t len,
                       struct sockaddr* addr,
                       socklen_t* addrlen,
                       DWORD flags = 0);

      ssize_t recvfrom(handle_t sock,
                       void* buf,
                       size_t len,
                       struct sockaddr* addr,
                       socklen_t* addrlen,
                       DWORD flags,
                       int timeout);

      // Send to.
      ssize_t sendto(handle_t sock,
                     const void* buf,
                     size_t len,
                     const struct sockaddr* addr,
                     socklen_t addrlen,
                     DWORD flags = 0);

      bool sendto(handle_t sock,
                  const void* buf,
                  size_t len,
                  const struct sockaddr* addr,
                  socklen_t addrlen,
                  DWORD flags,
                  int timeout);

#if HAVE_RECVMSG
      // Receive message.
      ssize_t recvmsg(handle_t sock, struct msghdr* msg);
      ssize_t recvmsg(handle_t sock, struct msghdr* msg, int timeout);
#endif // HAVE_RECVMSG

      // Send message.
      ssize_t sendmsg(handle_t sock, const struct msghdr* msg, DWORD flags = 0);
      bool sendmsg(handle_t sock,
                   const struct msghdr* msg,
                   DWORD flags,
                   int timeout);

      // Wait for socket to be readable.
      bool wait_readable(handle_t sock, int timeout);

      // Wait for socket to be writable.
      bool wait_writable(handle_t sock, int timeout);
    }
  }
}

#endif // NET_INTERNAL_SOCKET_H