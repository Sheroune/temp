#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

int sha256_verify(FILE *file, EVP_PKEY *pkey, unsigned char *sig, size_t siglen) {
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    if(!(ctx = EVP_MD_CTX_new())) {
        return -1;
    }

    if(!EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey)) {
        return -1;
    }

    char buf[512];
    size_t len;
    while((len = fread(buf, 1, sizeof(buf), file)) > 0) {
        if(!EVP_DigestVerifyUpdate(ctx, buf, len)) {
            return -1;
        }
    }

    if(ferror(file)) {
        return -1;
    }

    int v_res = EVP_DigestVerifyFinal(ctx, sig, siglen);
    if(v_res) {
        ret = 1;
    } else if(!v_res) {
        ret = 0;
    } else {
        ret = -1;
    }

    if(ctx) {
        EVP_MD_CTX_free(ctx);
    }

    return ret;
}


int main() {
    FILE *p_file = fopen("public_key.pem", "r");
    EVP_PKEY *public_key = PEM_read_PUBKEY(p_file, NULL, NULL, NULL);
    fclose(p_file);

    FILE *file_to_verify = fopen("test.c", "r");

    // Load the signature from a file
    FILE *sig_file = fopen("signature.bin", "rb");
    unsigned char *sig;
    size_t siglen;
    fseek(sig_file, 0, SEEK_END);
    siglen = ftell(sig_file);
    fseek(sig_file, 0, SEEK_SET);
    sig = malloc(siglen);
    fread(sig, 1, siglen, sig_file);
    fclose(sig_file);

    int v_res = sha256_verify(file_to_verify, public_key, sig, siglen);

    if(v_res == 1) {
        printf("Signature is correct!\n");
    } else {
        printf("Signature is incorrect!\n");
    }

    fclose(file_to_verify);

    return 0;
}
