#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include <yara_x.h>

#include "scanner.h"
#include "utils.h"

/* Internal structure to collect matches during scanning */
struct match_context {
  struct uav_yara_match *matches;
  size_t count;
  size_t capacity;
  char error_msg[256];
};

/* Add a matching to the ctx */
static void uav_yara_matching_rule(const struct YRX_RULE *rule, void *user_data) {
  (void) rule;
  struct match_context *ctx = user_data;

  if(ctx->count >= ctx->capacity) {
    ctx->capacity = ctx->capacity == 0 ? 8 : ctx->capacity * 2;
    ctx->matches = realloc(ctx->matches, ctx->capacity * sizeof(struct uav_yara_match));

    if(!ctx->matches) {
      snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Failed to allocate memory for matches");
      return;
    }
  }

  struct uav_yara_match *match = &ctx->matches[ctx->count];
  safe_strcpy(match->rule_name, "TODO", strlen("TODO") + 1);
  ctx->count += 1;
}

/* Initialize uav_scanner struct */
// TODO: check configuration files signatures
int uav_scanner_init(struct uav_scanner *s, const char *yr_path, const char *sig_path) {
  (void) sig_path;

  YRX_COMPILER *compiler = NULL;
  YRX_RESULT result;
  char *rulesrc = NULL;
  size_t nread;
  int ret = 1;

  if(!s) {
    errno = EINVAL;
    goto cleanup;
  }

  if(!yr_path) {
    ret = 0;
    goto cleanup;
  }

  /* Create a compiler */
  result = yrx_compiler_create(0, &compiler);
  if (result != YRX_SUCCESS) {
    fprintf(stderr, "[YARA] Failed to create compiler: %s\n", yrx_last_error());
    goto cleanup;
  }

  /* TODO: import all .yar files from a directory */
  /* Get rule source code */
  rulesrc = read_file(yr_path, &nread);
  if(!rulesrc) {
    fprintf(stderr, "[YARA] Failed to read rules at %s: %s\n", yr_path, yrx_last_error());
    goto cleanup;
  }

  /* Add rule to compiler*/
  result = yrx_compiler_add_source(compiler, rulesrc);
  if(result != YRX_SUCCESS) {
    fprintf(stderr, "[YARA] Warning: Failed to add %s: %s\n", yr_path, yrx_last_error());
    goto cleanup;
  }

  /* Build the rules */
  s->rules = yrx_compiler_build(compiler);

  ret = 0;
cleanup:
  if(compiler) yrx_compiler_destroy(compiler);
  if(ret != 0 && s->rules) yrx_rules_destroy(s->rules);

  return ret;
}

/* Free resources */
void uav_scanner_free(struct uav_scanner *s) {
  if(s == NULL) return;

  if(s->signatures) free(s->signatures);
  s->signatures = NULL;

  if(s->rules) yrx_rules_destroy(s->rules);
  s->rules = NULL;
}

int uav_yara_scan(const struct uav_scanner *s, const char *path, struct uav_yara_match **matches, size_t *nmatch) {

  (void) matches;

  if(!s || !path) {
    if(!nmatch) *nmatch = 0;
    return 0;
  }

  if(!nmatch) return 1;

  YRX_SCANNER *yara_scanner = NULL;
  enum YRX_RESULT result;
  int ret = 1;
  struct match_context ctx = {0};

  /* Create scanner */
  result = yrx_scanner_create(s->rules, &yara_scanner);
  if (result != YRX_SUCCESS) {
    fprintf(stderr, "[YARA] Failed to create scanner: %s\n", yrx_last_error());
    goto cleanup;
  }

  /* Configure callback */
  result = yrx_scanner_on_matching_rule(yara_scanner, uav_yara_matching_rule, (void *) &ctx);
  if (result != YRX_SUCCESS) {
    fprintf(stderr, "[YARA] Failed to create scanner: %s\n", yrx_last_error());
    return 1;
  }

  /* Scan file */
  result = yrx_scanner_scan_file(yara_scanner, path);
  if (result != YRX_SUCCESS) {
    fprintf(stderr, "[YARA] Scan failed: %s\n", yrx_last_error());
    goto cleanup;
  }

  *nmatch = ctx.count;
  *matches = ctx.matches;
  ret = 0;

cleanup:
  if (yara_scanner) yrx_scanner_destroy(yara_scanner);
 
  return ret;
}
