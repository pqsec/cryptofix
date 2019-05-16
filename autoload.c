#define _GNU_SOURCE /* for dladdr and Dl_info */
#include <dlfcn.h>
#include <stdio.h>

#include <openssl/engine.h>

static void fatal(const char *msg) {
  fputs(msg, stderr);
  exit(1);
}

static __attribute__((constructor)) void engine_preload(void) {
  // OpenSSL dynamic engine needs a filesystem path to the engine
  // so we determine our own filesystem path first
  Dl_info dinfo;
  int res = dladdr((const void *)engine_preload, &dinfo);
  if (0 == res) {
    fatal("failed to query engine module info");
  }
  if (NULL == dinfo.dli_fname) {
    fatal("failed to determine engine filesystem path");
  }
  ENGINE_load_dynamic();
  ENGINE *e = ENGINE_by_id("dynamic");
  if (NULL == e) {
    fatal("failed to load OpenSSL dynamic engine");
  }

  res = ENGINE_ctrl_cmd_string(e, "SO_PATH", dinfo.dli_fname, 0);
  if (res <= 0) {
    fatal("failed to set SO_PATH parameter for dynamic engine");
  }
  res = ENGINE_ctrl_cmd_string(e, "ID", "sha1-sha256", 0);
  if (res <= 0) {
    fatal("failed to set ID parameter for dynamic engine");
  }
  res = ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0);
  if (res <= 0) {
    fatal("failed to LOAD sha1-sha256 engine");
  }
  res = ENGINE_set_default(e, ENGINE_METHOD_ALL);
  if (res <= 0) {
    fatal("failed to set algorithms from sha1-sha256 engine as default");
  }
}
