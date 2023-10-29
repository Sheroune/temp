#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

int sha256_sign(FILE *file, EVP_PKEY *pkey, unsigned char **sig, size_t *siglen) {
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    if(!(ctx = EVP_MD_CTX_new())) {
        return -1;
    }

    if(!EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey)) {
        return -1;
    }

    char buf[512];
    size_t len;
    while((len = fread(buf, 1, sizeof(buf), file)) > 0) {
        if(!EVP_DigestSignUpdate(ctx, buf, len)) {
            return -1;
        }
    }

    if(ferror(file)) {
        return -1;
    }

    if(!EVP_DigestSignFinal(ctx, NULL, siglen)) {
        return -1;
    }

    if(!(*sig = malloc(*siglen))) {
        return -1;
    }

    if(!EVP_DigestSignFinal(ctx, *sig, siglen)) {
        return -1;
    }

    ret = 1;

    if(ctx) {
        EVP_MD_CTX_free(ctx);
    }

    return ret;
}


int main() {
    FILE *private_key_file = fopen("private_key.pem", "r");
    EVP_PKEY *private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);

    FILE *file_to_sign = fopen("test.c", "r");

    unsigned char *sig;
    size_t siglen;

    sha256_sign(file_to_sign, private_key, &sig, &siglen);

    // Save the signature to a file
    FILE *sig_file = fopen("signature.bin", "wb");
    fwrite(sig, 1, siglen, sig_file);
    fclose(sig_file);

    fclose(file_to_sign);
	printf("File signed successfully!\n")

    return 0;
}
