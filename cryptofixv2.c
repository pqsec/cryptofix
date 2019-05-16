#define _GNU_SOURCE /* for RTLD_NEXT */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type)
{
    static int (*real_fn)(EVP_MD_CTX *ctx, const EVP_MD *type) = NULL;
    if (!real_fn)
    {
        real_fn = dlsym(RTLD_NEXT, "EVP_DigestInit");
        if (!real_fn)
        {
            fputs("cannot find EVP_DigestInit", stderr);
            exit(1);
        }
    }
    
    if (type == EVP_sha1())
        return real_fn(ctx, EVP_sha256());
    else
        return real_fn(ctx, type);
}

int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
{
    static int (*real_fn)(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s) = NULL;
    if (!real_fn)
    {
        real_fn = dlsym(RTLD_NEXT, "EVP_DigestFinal");
        if (!real_fn)
        {
            fputs("cannot find EVP_DigestFinal", stderr);
            exit(1);
        }
    }

    if (EVP_MD_CTX_md(ctx) == EVP_sha256())
    {
        unsigned char sha256_md[SHA256_DIGEST_LENGTH];
        unsigned int sha256_md_size, err;
        
        err = real_fn(ctx, sha256_md, &sha256_md_size);
        fputs("replacing SHA1 with SHA256\n", stderr);
        memcpy(md, sha256_md, SHA_DIGEST_LENGTH);
        *s = SHA_DIGEST_LENGTH;
        return err;
    }
    else
        return real_fn(ctx, md, s);
}
