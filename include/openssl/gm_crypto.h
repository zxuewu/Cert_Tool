#ifndef HEADER_GM_CRYPTO_H
#define HEADER_GM_CRYPTO_H

#include <openssl/evp.h>


#ifdef __cplusplus
extern "C" {
#endif

const EVP_CIPHER *EVP_sm4_ecb(void);
const EVP_CIPHER *EVP_sm4_cbc(void);
const EVP_MD *EVP_sm3(void);
const EVP_MD *EVP_sm2_sign(void);

#ifdef __cplusplus
}
#endif
#endif
