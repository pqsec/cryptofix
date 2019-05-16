#include <stdio.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

static int hash(FILE *f)
{
    int err, i;
    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned int md_size;
    
    unsigned char buf[256];
    size_t bytes_read;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        errno = ENOMEM;
        return errno;
    }
    
    if (!EVP_DigestInit(ctx, EVP_sha1()))
    {
        EVP_MD_CTX_free(ctx);
        errno = EFAULT;
        return errno;
    }

    bytes_read = fread(buf, 1, sizeof(buf), f);
    while (bytes_read)
    {
        if (!EVP_DigestUpdate(ctx, buf, bytes_read))
        {
            EVP_MD_CTX_free(ctx);
            errno = EFAULT;
            return errno;
        }
        bytes_read = fread(buf, 1, sizeof(buf), f);
    }
    
    if (!feof(f))
    {
        EVP_MD_CTX_free(ctx);
        errno = EIO;
        return errno;
    }
    
    if (!EVP_DigestFinal(ctx, md, &md_size))
    {
        EVP_MD_CTX_free(ctx);
        errno = EFAULT;
        return errno;
    }

    for (i = 0; i < md_size; i++)
        printf("%02x", md[i]);
    puts("");
    
    return 0;
}
int main(int argc, char **argv)
{
    int err;
    FILE *f = stdin;
    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (!f) {
            perror(NULL);
            return errno;
        }
    }
    
    err = hash(f);
    if (err)
        perror(NULL);

    if (argc > 1)
        fclose(f);

    return err;
}