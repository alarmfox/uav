#define _XOPEN_SOURCE 500
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/evp.h>

/* ======================================== Constants =========================================== */
static const char YR_RULES_FILE [] = "data/av_yara_rules.yar";
static const char MB_SHA256_FILE [] = "data/av_sha256_signatures.txt";
static const char BUSYBOX_ZIP [] = "data/av_sandbox_busybox.zip";
static const char SANDBOX_CONFIG[] = "data/av_sandbox_configure.sh";
static const char SANDBOX_ENTRYPOINT[] = "data/av_sandbox_entrypoint.sh";
static const char hex[] = "0123456789abcdef";
/* =========================================== Types ============================================ */
#define SHA256_DIGEST_LEN 32
struct av_context {

  /* Each eleement of the array is a 32 byte digest */
  unsigned char (*signatures)[SHA256_DIGEST_LEN];
  size_t sigcount;
};

/* ====================================== Utils ================================================= */
/* Convert the current digest in a hex string */
static void digest_to_hex(const unsigned char *digest, int len, char *buf, int *hex_count) {

  if(digest == NULL || buf == NULL) return;

  for (int i = 0; i < len; ++i) {
    buf[i * 2] = hex[digest[i] >> 4];
    buf[i * 2 + 1] = hex[digest[i] & 0xF];
  }

  if(hex_count) *hex_count = len * 2;

}

static inline int hexval(char c) {
 if (c >= '0' && c <= '9') return c - '0';
 else if (c >= 'a' && c <='f') return  c - 'a' + 10;
 else if (c >= 'A' && c <='F') return c - 'A' + 10; 

 /* If reach here we are not parsing an hexadecimal value */
 assert(0);
}

static void digest_from_hex(const char *buf, int len, unsigned char *digest, int *digest_len) {

  if(!digest) return;

  assert(len % 2 == 0);
  for (int i = 0; i < len; i += 2) {
    int hi = hexval(buf[i]);
    int lo = hexval(buf[i + 1]);

    digest[i / 2] = (unsigned char) ((hi << 4) | lo);
  }

  if(digest_len) *digest_len = len / 2;
}

static int compare_digest(const unsigned char *a, const unsigned char *b, int len) {

  for(int i = 0; i < len; ++i) {
    if (a[i] != b[i]) return a[i] - b[i];
  }

  return 0;
}

static int extract_directory(const char *src, const char* output_path) {
  return 0;
}

static unsigned char *calculate_sha256_from_file(FILE *file, unsigned int *digest_len) {
  int ret;
  EVP_MD_CTX *mdctx;
  unsigned char *digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
  unsigned char buf[8192];
  size_t nbytes;

  if (!digest) return NULL;

  mdctx = EVP_MD_CTX_new();
  assert(mdctx);

  ret = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
  assert(ret == 1);

  while ((nbytes = fread(buf, 1, sizeof(buf), file)), nbytes != 0) {
    ret = EVP_DigestUpdate(mdctx, buf, nbytes);
    assert(ret == 1);
  }

  EVP_DigestFinal_ex(mdctx, digest, digest_len);
  assert(ret == 1);

  EVP_MD_CTX_free(mdctx);

  return digest;
}

int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
  int rv = remove(fpath);

  if (rv) fprintf(stderr, "cannot remove %s", fpath, strerror(errno));

  return rv;
}

static int rmtree(const char *path) {
  return nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}

static int copyfile(const char *src, const char *dst) {
  return 0;
}

/* ===================================== Sandbox ================================================ */
struct sandbox {
  char *root;
};

// TODO: add sandbox profile: server, desktop, minimal 
static int av_create_sandbox(struct sandbox *s, const char *root) {
  int ret;
  pid_t pid;

  s->root = root;

  pid = fork();

  switch(pid) {
  case -1:
    fprintf(stderr, "[SANDBOX] cannot create process: %s", strerror(errno));
    return 1;
  case 0:
    int ret = chroot(root);
    if(ret) {
      fprintf(stderr, "[SANDBOX] cannot chroot: %s\n", strerror(errno));
      _exit(1);
    }
    chdir("/");
    char *argv[] = { "/bin/sh", "av_sandbox_configure.sh", NULL };
    execv("/bin/sh", argv);

    _exit(EXIT_SUCCESS);
  default:
    waitpid(pid, 0, 0);
  }

  return 0;
}

static int av_run_program_in_sandbox(struct sandbox *s, const char *program) {
  pid_t pid = fork();

  switch(pid) {
  case -1:
    fprintf(stderr, "[SANDBOX] cannot create process: %s", strerror(errno));
    return 1;
  case 0:
    unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET);
    int ret = chroot(s->root);
    if(ret) {
      fprintf(stderr, "[SANDBOX] cannot chroot: %s\n", strerror(errno));
      _exit(1);
    }

    chdir("/");
    char *const argv[] = { "/bin/sh", "av_sandbox_entrypoint.sh", program, NULL };
    execv("/bin/sh", argv);

    _exit(EXIT_SUCCESS);
  default:
    waitpid(pid, 0, 0);
  }

  return 0;
}

static void av_destroy_sandbox(const struct sandbox *s) {
  int ret;
  ret = rmtree(s->root);

  if (ret) fprintf(stderr, "[SANDBOX] cannot remove %s: %s\n", s->root, strerror(errno));
}

/* ==================================== Commands ================================================= */
/* Scan a file */
static void av_scanfile(const struct av_context *ctx, const char *path) {
  unsigned int digest_len;
  unsigned char *digest;
  char hex_digest[65];
  FILE *file = fopen(path, "rb");
  assert(file);

  digest = calculate_sha256_from_file(file, &digest_len);
  fclose(file);

  assert(digest);
  assert(digest_len == SHA256_DIGEST_LEN);

  for(size_t i = 0; i < ctx->sigcount; ++i) {
    if(compare_digest(digest, ctx->signatures[i], SHA256_DIGEST_LEN) == 0) {
      digest_to_hex(digest, SHA256_DIGEST_LEN, hex_digest, 0);
      hex_digest[64] = 0;
      printf("[Check %zu] \"%s\" is a virus. Signature: 0x%s\n", i, path, hex_digest);
      break;
    }
  }

  OPENSSL_free(digest);
}

/* Initialize av_context struct */
// TODO: check configuration files signatures
static int av_init(struct av_context *ctx) {

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
  ctx->signatures = malloc(sizeof(unsigned char) * ctx->sigcount * SHA256_DIGEST_LEN);
  printf("%ld signatures \n", ctx->sigcount);

  /* Go back to first entry */
  fseek(file, 0, SEEK_SET);

  /* Skip all lines beginning with '#' */
  char line[256];
  size_t i = 0;
  while(fgets(line, 128, file) != NULL && i < ctx->sigcount) {
    if (line[0] == '#') continue;
    /* Remove '\r\n' */
    int k;
    digest_from_hex(line, SHA256_DIGEST_LEN * 2, ctx->signatures[i], &k);
    assert(k == SHA256_DIGEST_LEN);
    i += 1;
  }

  // TODO: parse yara rules

  fclose(file);
  return 0;
}

static void av_context_free(struct av_context *ctx) {
  if(ctx == NULL || ctx->signatures == NULL) return;

  free(ctx->signatures);
}

int main(void) {
  int ret;
  static struct av_context ctx = { 0 };
  struct sandbox s;
  const char sample[] = "sample.sh";

  ret = av_init(&ctx);

  if(ret) {
    fprintf(stderr, "cannot init av: (errno=%d) %s \nExiting.\n", errno, strerror(errno));
    return 1;
  }

  av_scanfile(&ctx, sample);

  ret = av_create_sandbox(&s, "sandbox");
  if(ret) goto exit;

  // ret = av_run_program_in_sandbox(&s, "ls");
  // if(ret) goto exit;

  av_context_free(&ctx);
exit:
  return 0;
}
