#define _GNU_SOURCE /* for RTLD_NEXT */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl)
{
    unsigned char sha256_md[SHA256_DIGEST_LENGTH];
    unsigned int sha256_md_size, err;

    static int (*real_fn)(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl)
 = NULL;
    if (!real_fn)
    {
        real_fn = dlsym(RTLD_NEXT, "EVP_Digest");
        if (!real_fn)
        {
            fputs("cannot find EVP_Digest", stderr);
            exit(1);
        }
    }
    
    if (type == EVP_sha1())
    {
        err = real_fn(data, count, sha256_md, &sha256_md_size, EVP_sha256(), impl);
        fputs("replacing SHA1 with SHA256\n", stderr);
        memcpy(md, sha256_md, SHA_DIGEST_LENGTH);
        *size = SHA_DIGEST_LENGTH;
        return err;
    }
    else
        return real_fn(data, count, md, size, type, impl);
}
