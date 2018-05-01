#ifndef SYS_UIO_H
#define SYS_UIO_H

struct iovec {
  unsigned long iov_len;
  char* iov_base;
};

#endif // SYS_UIO_H