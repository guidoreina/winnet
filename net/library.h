#ifndef NET_LIBRARY_H
#define NET_LIBRARY_H

#include <winsock2.h>

namespace net {
  class library {
    public:
      // Constructor.
      library();

      // Destructor.
      ~library();

      // Initialize.
      bool init();

      // Cleanup.
      void cleanup();

    private:
      bool _M_initialized;
  };

  inline library::library()
    : _M_initialized(false)
  {
  }

  inline library::~library()
  {
    cleanup();
  }

  inline bool library::init()
  {
    WORD version = MAKEWORD(2, 2);
    WSADATA wsadata;
    if (WSAStartup(version, &wsadata) == 0) {
      if ((LOBYTE(wsadata.wVersion) == 2) &&
          (HIBYTE(wsadata.wVersion) == 2)) {
        _M_initialized = true;
        return true;
      }

      WSACleanup();
    }

    return false;
  }

  inline void library::cleanup()
  {
    if (_M_initialized) {
      WSACleanup();

      _M_initialized = false;
    }
  }
}

#endif // NET_LIBRARY_H