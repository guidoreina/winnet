#include <stdio.h>
#include <errno.h>
#include "net/internal/socket/address/address.h"

namespace net {
  namespace internal {
    namespace socket {
      namespace address {
        static bool parse_port(const char* s, in_port_t& port)
        {
          unsigned n = 0;
          while (*s) {
            if ((*s >= '0') &&
                (*s <= '9') &&
                ((n = (n * 10) + (*s - '0')) <= 65535)) {
              s++;
            } else {
              return false;
            }
          }

          if (n > 0) {
            port = static_cast<in_port_t>(n);
            return true;
          }

          return false;
        }

        bool extract_ip_port(const char* address, char* ip, in_port_t& port)
        {
          // Search last colon.
          const char* colon = nullptr;
          const char* p = address;
          while (*p) {
            if (*p == ':') {
              colon = p;
            }

            p++;
          }

          if (colon) {
            size_t len;
            if ((len = colon - address) > 0) {
              if (*address == '[') {
                if ((len > 2) && (colon[-1] == ']')) {
                  // Skip '['.
                  address++;

                  len -= 2;
                } else {
                  return false;
                }
              }

              if (len < INET6_ADDRSTRLEN) {
                if (parse_port(colon + 1, port)) {
                  memcpy(ip, address, len);
                  ip[len] = 0;

                  return true;
                }
              }
            }
          }

          return false;
        }

        bool build_ipv4(const char* address,
                        in_port_t port,
                        struct sockaddr_in* addr,
                        socklen_t* addrlen)
        {
          if (inet_pton(AF_INET, address, &addr->sin_addr) == 1) {
            addr->sin_family = AF_INET;
            addr->sin_port = htons(port);
            memset(addr->sin_zero, 0, sizeof(addr->sin_zero));

            *addrlen = sizeof(struct sockaddr_in);

            return true;
          }

          return false;
        }

        bool build_ipv6(const char* address,
                        in_port_t port,
                        struct sockaddr_in6* addr,
                        socklen_t* addrlen)
        {
          if (inet_pton(AF_INET6, address, &addr->sin6_addr) == 1) {
            addr->sin6_family = AF_INET6;
            addr->sin6_port = htons(port);
            addr->sin6_flowinfo = 0;
            addr->sin6_scope_id = 0;

            *addrlen = sizeof(struct sockaddr_in6);

            return true;
          }

          return false;
        }

        const char* ipv4_to_string(const struct sockaddr_in* addr,
                                   char* s,
                                   size_t n)
        {
          if (inet_ntop(AF_INET,
                        const_cast<in_addr*>(&addr->sin_addr),
                        s,
                        n)) {
            size_t len = strlen(s);
            size_t left = n - len;

            if (_snprintf_s(s + len,
                            left,
                            _TRUNCATE,
                            ":%u",
                            ntohs(addr->sin_port)) > 0) {
              return s;
            } else {
              errno = ENOSPC;
            }
          }

          return nullptr;
        }

        const char* ipv6_to_string(const struct sockaddr_in6* addr,
                                   char* s,
                                   size_t n)
        {
          if (n > 1) {
            if (inet_ntop(AF_INET6,
                          const_cast<in6_addr*>(&addr->sin6_addr),
                          s + 1,
                          n - 1)) {
              size_t len = 1 + strlen(s + 1);
              size_t left = n - len;

              if (_snprintf_s(s + len,
                              left,
                              _TRUNCATE,
                              "]:%u",
                              ntohs(addr->sin6_port)) > 0) {
                *s = '[';

                return s;
              } else {
                errno = ENOSPC;
              }
            }
          } else {
            errno = ENOSPC;
          }

          return nullptr;
        }
      }
    }
  }
}
