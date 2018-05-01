#include <stdlib.h>
#include <string.h>
#include "net/socket.h"

bool net::socket::address::operator==(const struct sockaddr& addr) const
{
  if (_M_addr.ss_family == addr.sa_family) {
    switch (_M_addr.ss_family) {
      case AF_INET:
        return internal::socket::address::equal(
                 reinterpret_cast<const struct sockaddr_in*>(&_M_addr),
                 reinterpret_cast<const struct sockaddr_in*>(&addr)
               );
      case AF_INET6:
        return internal::socket::address::equal(
                 reinterpret_cast<const struct sockaddr_in6*>(&_M_addr),
                 reinterpret_cast<const struct sockaddr_in6*>(&addr)
               );
    }
  }

  return false;
}

net::socket::address&
net::socket::address::operator=(const struct sockaddr& addr)
{
  switch (addr.sa_family) {
    case AF_INET:
      memcpy(&_M_addr, &addr, sizeof(struct sockaddr_in));
      _M_addrlen = sizeof(struct sockaddr_in);

      break;
    case AF_INET6:
      memcpy(&_M_addr, &addr, sizeof(struct sockaddr_in6));
      _M_addrlen = sizeof(struct sockaddr_in6);

      break;
  }

  return *this;
}
