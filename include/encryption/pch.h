#pragma once

// Precompiled header to reduce compile time for commonly included heavy headers

// Standard headers
#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>
#include <string>

#if ENCRYPTION_USE_OPENSSL
  // OpenSSL heavy headers
  #include <openssl/evp.h>
  #include <openssl/ssl.h>
  #include <openssl/x509.h>
#endif

// Windows heavy header guarded by platform macro
#ifdef _WIN32
// winsock2 should be included before windows.h if networking is used
#include <winsock2.h>
#include <windows.h>
#endif
