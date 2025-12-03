#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>
#include <openssl/evp.h>
#include <yara_x.h>
#include <zip.h>

/* ======================================== Constants ============================================ */
static const char YR_RULES_URL [] = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";
static const char YR_RULES_ZIP [] = "packages/core/yara-rules-core.yar";
static const char YR_RULES_FILE [] = "yr_rules.yar";

static const char MB_SHA256_URL [] = "https://bazaar.abuse.ch/export/txt/sha256/full/";
static const char MB_SHA256_ZIP [] = "full_sha256.txt";
static const char MB_SHA256_FILE [] = "mb_sha256.txt";

struct sandbox {
  char *rootdir;
};

static int extract_single_file(const char *zipname, const char *zip_internal_path, const char *output_path) {

  int err = 0;
  char buf[8192];
  zip_t *za;
  zip_file_t *zf;
  struct zip_stat st;
  zip_int64_t idx;

  /* Open the file as a zip */
  za = zip_open(zipname, ZIP_RDONLY, &err);
  if (!za) {
    zip_error_to_str(buf, sizeof(buf), err, errno);
    fprintf(stderr, "[ZIP]: can't open zip archive: %s\n", buf);
    return 1;
  }

  idx = zip_name_locate(za, zip_internal_path, 0);
  if (idx < 0) {
    zip_close(za);
    fprintf(stderr, "[ZIP]: cannot find file: %s\n", zip_internal_path);
    return 1;
  }

  if (zip_stat_index(za, idx, 0, &st) != 0) {
    zip_error_to_str(buf, sizeof(buf), err, errno);
    fprintf(stderr, "[ZIP]: cannot stat: %s\n", buf);
    return 1;
  }
 
  zf = zip_fopen_index(za, idx, 0);
  if (!zf) {
    zip_close(za);
    return 1;
  }

  FILE *out = fopen(output_path, "wb");
  if (!out) {
    zip_fclose(zf);
    zip_close(za);
    return 1;
  }

  zip_int64_t total = 0;

  while (total < st.size) {
    zip_int64_t len = zip_fread(zf, buf, sizeof(buf));
    if (len < 0) break;
    fwrite(buf, 1, (size_t)len, out);
    total += len;
  }

  fclose(out);
  zip_fclose(zf);
  zip_close(za);
  return 0;
}

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *stream) {
  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}

static int download_file(const char *url, const char *output_path) {

  CURL *curl;
  CURLcode res;
  FILE *pagefile;

  res = curl_global_init(CURL_GLOBAL_ALL);
  if(res) {
    fprintf(stderr, "Could not init libcurl\n");
    return (int)res;
  }

  pagefile = fopen(output_path, "wb");

  assert(pagefile);

  /* init the curl session */
  curl = curl_easy_init();

  if(!curl) {
    fprintf(stderr, "Could not init libcurl\n");
    return 1;
  }

  /* set URL to get here */
  curl_easy_setopt(curl, CURLOPT_URL, url);

  /* Switch on full protocol/debug output while testing */
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* disable progress meter, set to 0L to enable it */
  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

  /* send all data to this function  */
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);

  /* follow redirects */
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

  /* write the page body to this file handle */
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, pagefile);

  /* get it! */
  res = curl_easy_perform(curl);

  // TODO: inspect return code
  assert(res == CURLE_OK);

  fclose(pagefile);

  /* cleanup curl stuff */
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}

static int download_and_extract_single_file(const char *url, const char *zip_internal_path, const char *output_path) {
  char tempname[] = "/tmp/linux_av_XXXXXX";
  int fd = mkstemp(tempname);

  if(fd < 0) {
    fprintf(stderr, "cannot create tempfile");
    return 1;
  }

  /* Download YARA_RULES */
  download_file(url, tempname);
  extract_single_file(tempname, zip_internal_path, output_path);
  close(fd);
  remove(tempname);
  return 0;
}

static int setup() {
  int ret;

  /* Download and extract yara rules */
  ret = download_and_extract_single_file(YR_RULES_URL, YR_RULES_ZIP, YR_RULES_FILE);

  if (ret) return ret;

  /* Download and extract malware bazaar hashes */
  return download_and_extract_single_file(MB_SHA256_URL, MB_SHA256_ZIP, MB_SHA256_FILE);
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

static void scanfile(const char *path) {
  unsigned int digest_len;
  unsigned char *digest;
  char hex_digest[128];
  FILE *file = fopen(path, "rb");
  assert(file);

  digest = calculate_sha256_from_file(file, &digest_len);
  fclose(file);
  assert(digest);
  assert(digest_len == 32);

  for (int i = 0; i < digest_len; ++i)
    sprintf(hex_digest + (i * 2), "%02x", digest[i]);
  hex_digest[digest_len * 2] = 0;

  printf("0x%s\n", hex_digest);

  file = fopen(MB_SHA256_FILE, "r");
  assert(file);

  char line[128];
  while(fgets(line, sizeof(line), file) != NULL) {
    if(strncmp(line, hex_digest, digest_len * 2) == 0) {
      printf("found malware\n");
    }
  }

  fclose(file);
  OPENSSL_free(digest);
}


int main(void) {

  scanfile("sample.sh");
  return 0;
}
