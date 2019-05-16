#include <stdio.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

static int hash(FILE *f)
{
    int err, i;
    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned int md_size;
    
    unsigned char buf[4096], *pos;
    size_t bytes_read;

    pos = buf;
    bytes_read = fread(buf, 1, buf + sizeof(buf) - pos, f);
    while (bytes_read && pos < (buf + sizeof(buf)))
    {
        pos += bytes_read;
        bytes_read = fread(buf, 1, buf + sizeof(buf) - pos, f);
    }
    
    if (!feof(f))
    {
        errno = EIO;
        return errno;
    }
    
    if (!EVP_Digest(buf, pos - buf, md, &md_size, EVP_sha1(), NULL))
    {
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