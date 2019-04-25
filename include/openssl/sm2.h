// \file:sm2.h
//SM2 Algorithm
//2011-11-09
//author:goldboar
//email:goldboar@163.com
//comment:2011-11-10 sm2-sign-verify sm2-dh


#ifndef SM2_H
#define SM2_H
#include <openssl/ec.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

typedef struct SM2_CIPHER_TEXT_st
{
	ASN1_INTEGER *C1_x;
	ASN1_INTEGER *C1_y;
	ASN1_OCTET_STRING *C3;
	ASN1_OCTET_STRING *C2;

} SM2_CIPHER_TEXT;



#ifdef __cplusplus
extern "C" {
#endif
DECLARE_ASN1_FUNCTIONS(SM2_CIPHER_TEXT)

int SM2_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp);

//SM2_sign_ex
int	SM2_sign_ex(int type, const unsigned char *dgst, int dlen, unsigned char 
	*sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);

//SM2_sign
int	SM2_sign(int type, const unsigned char *dgst, int dlen, unsigned char 
		*sig, unsigned int *siglen, EC_KEY *eckey);

//SM2_verify
int SM2_verify(int type, const unsigned char *dgst, int dgst_len,
		const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);

//SM2 DH, comupting shared point
//int SM2_DH_key(const EC_GROUP * group,const EC_POINT *b_pub_key_r, const EC_POINT *b_pub_key, const BIGNUM *a_r,EC_KEY *a_eckey,
//			   unsigned char *outkey,size_t keylen);

int sm2_encrypt(EC_KEY *eckey, BN_CTX *ctx_in, const unsigned char* data, int data_len, unsigned char* result);

int sm2_encrypt_der(EC_KEY *eckey, BN_CTX *ctx_in, const unsigned char* data, int data_len, unsigned char* result);

int sm2_encrypt_ex(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM *k_in, const unsigned char* data, int data_len, unsigned char* result);

int sm2_encrypt_ex_der(EC_KEY *eckey, BN_CTX *ctx, BIGNUM *k_in, const unsigned char* data, int data_len, unsigned char* result);

int sm2_decrypt_der(EC_KEY *eckey, BN_CTX *ctx_in, const unsigned char* data_der, int data_len, unsigned char* result);

int sm2_decrypt(EC_KEY *eckey, BN_CTX *ctx_in, const unsigned char* cipher_data, int cipher_data_len, unsigned char* plain_data);

int kdf(const unsigned char *share, size_t sharelen, size_t keylen, unsigned char *outkey);

int z(const unsigned char *id, int id_len, const EC_GROUP *group, const EC_POINT *pub_point, unsigned char *digest, BN_CTX *ctx);

int bn2bin(BIGNUM *bn, unsigned char *to);


int init_group_gb(EC_GROUP *group, BN_CTX * ctx);


int init_test_gb(EC_GROUP *group, BN_CTX * ctx);

int sm2_key_exchange(EC_GROUP *group, EC_POINT *Q_local, BIGNUM *d, EC_POINT *Q_remote, EC_POINT *random_point_local,
					 EC_POINT *random_point_remote, BIGNUM * random, unsigned char *id_local, int id_length_local,
					 unsigned char * id_remote, int id_length_remote, int active, unsigned char *key, int key_length
					 ,BN_CTX *ctx);

#ifdef __cplusplus
}
#endif
#endif

