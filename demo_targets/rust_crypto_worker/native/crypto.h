#ifndef CRYPTO_WORKER_H
#define CRYPTO_WORKER_H

#include <ffi.h>
#include <openssl/ssl.h>

int crypto_worker_digest(const unsigned char *input, size_t length);

#endif
