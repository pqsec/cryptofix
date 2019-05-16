#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

static const char *engine_id = "sha1-sha256";
static const char *engine_name =
    "An engine, which converts SHA1 to SHA256 for better security";

static int digest_init(EVP_MD_CTX *ctx) {
  return SHA256_Init(EVP_MD_CTX_md_data(ctx));
}

static int digest_update(EVP_MD_CTX *ctx, const void *data, size_t count) {
  return SHA256_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int digest_final(EVP_MD_CTX *ctx, unsigned char *md) {
  char sha256_md[SHA256_DIGEST_LENGTH];
  int err;

  err = SHA256_Final(sha256_md, EVP_MD_CTX_md_data(ctx));
  fputs("replacing SHA1 with SHA256\n", stderr);
  memcpy(md, sha256_md, SHA_DIGEST_LENGTH);
  return err;
}

static EVP_MD *digest_meth = NULL;
static int digest_nids[] = {NID_sha1, 0};
static int digests(ENGINE *e, const EVP_MD **digest, const int **nids,
                   int nid) {
  if (!digest) {
    *nids = digest_nids;
    return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
  }
  switch (nid) {
  case NID_sha1:
    if (digest_meth == NULL) {
      digest_meth = EVP_MD_meth_new(NID_sha1, NID_sha1WithRSAEncryption);
      if (!digest_meth) {
        return 0;
      }
      if (!EVP_MD_meth_set_result_size(digest_meth, SHA_DIGEST_LENGTH) ||
          !EVP_MD_meth_set_flags(digest_meth, EVP_MD_FLAG_DIGALGID_ABSENT) ||
          !EVP_MD_meth_set_init(digest_meth, digest_init) ||
          !EVP_MD_meth_set_update(digest_meth, digest_update) ||
          !EVP_MD_meth_set_final(digest_meth, digest_final) ||
          !EVP_MD_meth_set_cleanup(digest_meth, NULL) ||
          !EVP_MD_meth_set_ctrl(digest_meth, NULL) ||
          !EVP_MD_meth_set_input_blocksize(digest_meth, SHA_CBLOCK) ||
          !EVP_MD_meth_set_app_datasize(
              digest_meth, sizeof(EVP_MD *) + sizeof(SHA256_CTX)) ||
          !EVP_MD_meth_set_copy(digest_meth, NULL)) {

        goto err;
      }
    }
    *digest = digest_meth;
    return 1;
  default:
    *digest = NULL;
    return 0;
  }

err:
  if (digest_meth) {
    EVP_MD_meth_free(digest_meth);
    digest_meth = NULL;
  }
  return 0;
}

static int engine_init(ENGINE *e) {
  return 1;
}

static int engine_finish(ENGINE *e) {
  if (digest_meth) {
    EVP_MD_meth_free(digest_meth);
    digest_meth = NULL;
  }
  return 1;
}

static int bind(ENGINE *e, const char *id) {
  if (!ENGINE_set_id(e, engine_id)) {
    goto err;
  }
  if (!ENGINE_set_name(e, engine_name)) {
    goto err;
  }
  if (!ENGINE_set_init_function(e, engine_init)) {
    goto err;
  }
  if (!ENGINE_set_finish_function(e, engine_finish)) {
    goto err;
  }
  if (!ENGINE_set_digests(e, digests)) {
    goto err;
  }
  return 1;
err:
  return 0;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
