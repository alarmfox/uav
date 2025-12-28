#include "utils.h"

#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <zip.h>

static inline int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  else if (c >= 'a' && c <='f') return  c - 'a' + 10;
  else if (c >= 'A' && c <='F') return c - 'A' + 10; 

  /* If here, we are not parsing an hexadecimal value */
  assert(0);
}

/* Perform safe strcopy */
void safe_strcpy(char *dst, const char *src, size_t size) {
  /* Sanity check */
  if(!src || !dst) return;

  size_t len = strnlen(src, size - 1);
  memcpy(dst, src, len);
  dst[len] = '\0';
}

/* Convert the current digest in a hex string. The hexstring must be null terminated by the caller */
ssize_t digest_to_hex(const unsigned char *digest, int len, char *buf) {
  static const char hex[] = "0123456789abcdef";

  if(digest == NULL || buf == NULL) return -1;

  for (int i = 0; i < len; ++i) {
    buf[i * 2] = hex[digest[i] >> 4];
    buf[i * 2 + 1] = hex[digest[i] & 0xF];
  }

  return len * 2;
}


/* Parses an hex digest and builds the original numeric digest value */
ssize_t digest_from_hex(const char *buf, int len, unsigned char *digest) {

  if(!digest) return -1;

  assert(len % 2 == 0);
  for (int i = 0; i < len; i += 2) {
    int hi = hexval(buf[i]);
    int lo = hexval(buf[i + 1]);

    digest[i / 2] = (unsigned char) ((hi << 4) | lo);
  }

  return len / 2;
}

/* Compare 2 digests. This assumes that both digests have same length.
 * Returns 0 if they are the same (byte by byte) or the difference of the first non equal byte */
int compare_digest(const unsigned char *a, const unsigned char *b, int len) {

  for(int i = 0; i < len; ++i) {
    if (a[i] != b[i]) return a[i] - b[i];
  }

  return 0;
}

/* Extract src zip file in output directory */
int extract_directory(const char *src, const char *output_path) {
  int ret;
  zip_t *za = zip_open(src, ZIP_RDONLY, &ret);
  zip_int64_t num_entries, nread;
  zip_uint8_t opsys;
  zip_uint32_t attributes;
  struct zip_stat st;
  zip_file_t *zf = NULL;
  FILE *f = NULL;
  char filepath[512], buf[8 * 1024];

  if (!za) {
    fprintf(stderr, "[SANDBOX] cannot open zip: error %d\n", ret);
    return -1;
  }

  num_entries = zip_get_num_entries(za, 0);

  for (zip_int64_t i = 0; i < num_entries; i++) {
    const char *name = zip_get_name(za, i, 0);
    if (!name) continue;

    snprintf(filepath, sizeof(filepath), "%s/%s", output_path, name);

    /* Get stat for the current file */
    zip_stat_index(za, i, 0, &st);

    /* Create directory */
    if (name[strlen(name) - 1] == '/') {
      mkdir(filepath, 0755);
      /* Skip to permission path */
      goto perm;
    }

    /* Open file in archive */
    zf = zip_fopen_index(za, i, 0);
    if (!zf) continue;

    /* Open destination file */
    f = fopen(filepath, "wb");
    if (!f) {
      zip_fclose(zf);
      continue;
    }

    /* Extract file byte by byte */
    while ((nread = zip_fread(zf, buf, sizeof(buf))) > 0) {
      fwrite(buf, 1, nread, f);
    }

    fclose(f);
    zip_fclose(zf);

perm:
    /* Retrieve permission and restore them */
    ret = zip_file_get_external_attributes(za, i, ZIP_FL_UNCHANGED, &opsys, &attributes);

    if(ret){
      fprintf(stderr, "[ZIP] cannot get permissions for %s\n", filepath);
      continue;
    }

    /* Check if permission were for UNIX */
    if (opsys == ZIP_OPSYS_UNIX ){
      /* Apply permissions with chmod */
      ret = chmod(filepath, attributes >> 16);
      if(ret) fprintf(stderr, "[ZIP] cannot set permissions on %s: %s\n", filepath, strerror(errno));

    } else {
      fprintf(stderr, "[ZIP] file was not compressed on Unix\n");
      exit(1);
    }
  }

  zip_close(za);
  return 0;
}

/* Computes SHA256 from a file */
ssize_t calculate_sha256_from_file(FILE *file, unsigned char *digest) {

  if(!digest) return -1;

  int ret;
  EVP_MD_CTX *mdctx;
  unsigned char buf[8192];
  size_t nbytes;
  unsigned int digestlen;

  mdctx = EVP_MD_CTX_new();
  assert(mdctx);

  ret = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
  assert(ret == 1);

  while ((nbytes = fread(buf, 1, sizeof(buf), file)), nbytes != 0) {
    ret = EVP_DigestUpdate(mdctx, buf, nbytes);
    assert(ret == 1);
  }

  ret = EVP_DigestFinal_ex(mdctx, digest, &digestlen);
  assert(ret == 1);
  assert(digestlen == SHA256_DIGEST_LEN);

  EVP_MD_CTX_free(mdctx);

  return digestlen;
}

static int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
  (void)sb;
  (void)typeflag;
  (void)ftwbuf;

  int rv = remove(fpath);

  if (rv) fprintf(stderr, "cannot remove %s: %s\n", fpath, strerror(errno));

  return rv;
}

/* Delete a directory recursively */
int rmtree(const char *path) {
  return nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}

/* Copy file from src to dst. Perform a byte-byte copy */
int copyfile(const char *src, const char *dst) {
  FILE *fsrc = NULL, *fdst = NULL;
  unsigned char buf[8192];
  size_t nread;

  fsrc = fopen(src, "rb");
  if (!fsrc) {
    fprintf(stderr, "[SANDBOX] cannot open source %s: %s\n", src, strerror(errno));
    return -1;
  }

  fdst = fopen(dst, "wb");
  if (!fdst) {
    fprintf(stderr, "[SANDBOX] cannot open destination %s: %s\n", dst, strerror(errno));
    fclose(fsrc);
    return -1;
  }

  while ((nread = fread(buf, 1, sizeof(buf), fsrc)) > 0) {
    if (fwrite(buf, 1, nread, fdst) != nread) {
      fprintf(stderr, "[SANDBOX] write error: %s\n", strerror(errno));
      goto cleanup;
    }
  }

  if (ferror(fsrc)) {
    fprintf(stderr, "[SANDBOX] read error: %s\n", strerror(errno));
    goto cleanup;
  }

cleanup:
  if (fsrc) fclose(fsrc);
  if (fdst) fclose(fdst);
  return 0;
}

/* Write `data` in `path` */
int write_file(const char *path, const char *data, size_t len) {
  int fd, ret = -1;
  ssize_t written;

  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    fprintf(stderr, "[UTILS] cannot open %s: %s\n", path, strerror(errno));
    return -1;
  }

  written = write(fd, data, len);
  if (written < 0 || (size_t)written != len) {
    fprintf(stderr, "[UTILS] write failed: %s\n", strerror(errno));
    goto cleanup;
  }

  ret = 0;

cleanup:
  close(fd);
  return ret;
}

/* Write `str` in `path` */
int write_file_str(const char *path, const char *str) {
  return write_file(path, str, strlen(str));
}

/* Read a file */
ssize_t read_file(const char *path, char *buf, size_t size) {
  int fd;
  ssize_t nread;

  fd = open(path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "[UTILS] cannot open %s: %s\n", path, strerror(errno));
    return -1;
  }

  nread = read(fd, buf, size - 1);
  close(fd);

  if (nread < 0) {
    fprintf(stderr, "[UTILS] read failed: %s\n", strerror(errno));
    return -1;
  }

  buf[nread] = '\0';
  return nread;
}
