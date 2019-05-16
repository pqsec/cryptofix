#include <stdio.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

static int hash(FILE *f)
{
    int err, i;
    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned int md_size = sizeof(md);
    
    unsigned char buf[256];
    int bytes_read;
    
    BIO *filebio, *sha1bio;

    filebio = BIO_new_fp(f, BIO_NOCLOSE);
    if (!filebio)
    {
        errno = ENOMEM;
        return errno;
    }
    
    sha1bio = BIO_new(BIO_f_md());
    if (!sha1bio)
    {
        BIO_free(filebio);
        errno = ENOMEM;
        return errno;
    }

    BIO_set_md(sha1bio, EVP_sha1());
    BIO_push(sha1bio, filebio);

    bytes_read = BIO_read(sha1bio, buf, sizeof(buf));
    while (bytes_read > 0)
    {
        bytes_read = BIO_read(sha1bio, buf, sizeof(buf));
    }
    
    if (bytes_read < 0)
    {
        BIO_free_all(sha1bio);
        errno = EIO;
        return errno;
    }

    if (BIO_gets(sha1bio, md, sizeof(md)) <= 0)
    {
        BIO_free_all(sha1bio);
        errno = EFAULT;
        return errno;
    }

    BIO_free_all(sha1bio);

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