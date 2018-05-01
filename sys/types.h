#ifndef SYS_TYPES_H
#define SYS_TYPES_H

#include <stdint.h>

typedef long ssize_t;
typedef uint16_t in_port_t;
typedef unsigned short sa_family_t;

struct msghdr {
  LPSOCKADDR msg_name;
  INT msg_namelen;
  LPWSABUF msg_iov;
  DWORD msg_iovlen;
  WSABUF msg_control;
  DWORD msg_flags;
};

#endif // SYS_TYPES_H