#ifndef __UAV_CONTEXT_H
#define __UAV_CONTEXT_H

#include <stddef.h>

#define SHA256_DIGEST_LEN 32

static const char MB_SHA256_FILE [] = "data/uav_sha256_signatures.txt";

struct uav_context {
  /* Each element of the array is a 32 byte digest */
  unsigned char (*signatures)[SHA256_DIGEST_LEN];
  size_t sigcount;
};
#endif // !__UAV_CONTEXT_H
