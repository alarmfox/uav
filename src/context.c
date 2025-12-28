#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include "context.h"
#include "utils.h"
/* Initialize av_context struct */
// TODO: check configuration files signatures
int uav_context_init(struct uav_context *ctx) {
  /*
   * Format:
   * - preamble
   * - signatures
   * - number of signatures:  # Number of entries: 1015158\r\n
   */
  char size[32];
  char c; 
  int n = 0;
  long pos = 0;
  FILE* file = fopen(MB_SHA256_FILE, "r");

  if(!file) return 1;

  /* Jump to the end of file */
  fseek(file, 0L, SEEK_END);

  /* Skip '\r\n' */
  fseek(file, -2, SEEK_CUR);

  /* Read the number of entries backwards */
  pos = ftell(file);

  do {
    fseek(file, pos--, SEEK_SET);
    c = fgetc(file);
    size[n++] = c; 
  } while(pos >= 0 && c != ' ');
  size[n] = 0;

  // Put in correct byte order for atol
  for(int i = 0; i < n/2; ++i) {
    char tmp = size[i];

    /* Swap with other half array */
    size[i] = size[n - i -1];
    size[n - i - 1] = tmp;
  }

  ctx->sigcount = atol(size);
  ctx->signatures = malloc(sizeof(*ctx->signatures) * ctx->sigcount);

  /* Go back to first entry */
  fseek(file, 0, SEEK_SET);

  /* Skip all lines beginning with '#' */
  char line[128];
  size_t i = 0;
  while(fgets(line, 128, file) != NULL && i < ctx->sigcount) {
    if (line[0] == '#') continue;
    ssize_t k = digest_from_hex(line, SHA256_DIGEST_LEN * 2, ctx->signatures[i]);
    assert(k == SHA256_DIGEST_LEN);
    i += 1;
  }

  fclose(file);
  return 0;
}

/* Scan a single file. Compute its hash and compare against signature lists */
int uav_context_scanfile(const struct uav_context *ctx, const char *path, unsigned char *odigest, int *diglen) {
  ssize_t len;
  unsigned char digest[256];
  int ismalware = 0;
  FILE *file = fopen(path, "rb");
  assert(file);

  len = calculate_sha256_from_file(file, digest);
  fclose(file);

  assert(digest);
  assert(len == SHA256_DIGEST_LEN);

  for(size_t i = 0; i < ctx->sigcount && !ismalware; ++i) {
    if(compare_digest(digest, ctx->signatures[i], SHA256_DIGEST_LEN) == 0) ismalware = 1;
  }

  /* Save file digest in odigest */
  memcpy(odigest, digest, SHA256_DIGEST_LEN);
  if(diglen) *diglen = SHA256_DIGEST_LEN;

  return ismalware;
}

void uav_context_free(struct uav_context *ctx) {
  if(ctx == NULL || ctx->signatures == NULL) return;

  free(ctx->signatures);
}
