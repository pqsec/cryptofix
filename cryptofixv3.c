#define _GNU_SOURCE /* for RTLD_NEXT */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg)
{
    static long (*real_fn)(BIO *bp, int cmd, long larg, void *parg) = NULL;
    if (!real_fn)
    {
        real_fn = dlsym(RTLD_NEXT, "BIO_ctrl");
        if (!real_fn)
        {
            fputs("cannot find BIO_ctrl", stderr);
            exit(1);
        }
    }
    
    if (cmd == BIO_C_SET_MD && parg == EVP_sha1())
        return real_fn(bp, cmd, larg, (void *)EVP_sha256());
    else
        return real_fn(bp, cmd, larg, parg);
}

int BIO_gets(BIO *bp, char *buf, int size)
{
    EVP_MD *md = NULL;
    static int (*real_fn)(BIO *bp, char *buf, int size) = NULL;
    if (!real_fn)
    {
        real_fn = dlsym(RTLD_NEXT, "BIO_gets");
        if (!real_fn)
        {
            fputs("cannot find BIO_gets", stderr);
            exit(1);
        }
    }

    if (BIO_method_type(bp) == BIO_TYPE_MD && BIO_get_md(bp, &md))
    {
        if (md == EVP_sha256()) {
            char sha256_md[SHA256_DIGEST_LENGTH];
            int err;
    
            if (size < SHA_DIGEST_LENGTH)
                return 0;
        
            err = real_fn(bp, sha256_md, sizeof(sha256_md));
            fputs("replacing SHA1 with SHA256\n", stderr);
            memcpy(buf, sha256_md, size);
            return err;
        }
    }

    return real_fn(bp, buf, size);
}
