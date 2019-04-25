
#ifndef HEADER_GM_H
#define HEADER_H
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

int SSL_CTX_use_encrypt_cert_file(SSL_CTX *ctx, const char *file);
int SSL_CTX_use_encrypt_cert(SSL_CTX *ctx, X509 *cert);
int SSL_CTX_use_encrypt_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_encrypt_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);
int SSL_CTX_use_sign_cert(SSL_CTX *ctx, X509 *cert);
int init_gm_ctx(SSL_CTX *ctx);
void GM_load_library(void);
void GM_load_library_ex(void);

const SSL_METHOD *GMv1_1_client_method(void);

#ifdef __cplusplus
}
#endif

#endif