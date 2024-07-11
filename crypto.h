#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "mbedtls/aes.h"
#include "mbedtls/cmac.h"
#include "mbedtls/md.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define u8 unsigned char
#define MBEDTLS_AES_BLOCK_SIZE 16
#define SHA256_MAC_LEN 32
static const u8 zero[AES_BLOCK_SIZE];

void put_le16(uint16_t data, uint8_t *buffer) ;
void *memdup(const void *src, size_t len);
void handleErrors(void) ;

unsigned char *base64_gen_decode(const char *src, size_t len,
					 size_t *out_len, const char *table);
u8* create_ec_key_from_der(const unsigned char* der_data, size_t der_len, size_t *key_len);
EVP_PKEY* generate_ec_key(void);
EC_KEY *create_ec_key_from_private_key_bytes(const unsigned char *priv_key_bytes, size_t priv_key_len) ;
EC_KEY *convert_bytes_to_EC_KEY(const unsigned char *pub_key_bytes, size_t pub_key_len);
int encode_ec_public_key(EC_KEY *ec_key, unsigned char **out_pub_key, size_t *out_pub_key_len);
int calculate_public_key_hash(EC_KEY *eckey, unsigned char *hash);
int encode_ec_private_key(EVP_PKEY *pkey, unsigned char **out_priv_key, size_t *out_priv_key_len);
void print_key(EVP_PKEY *pkey);
void print_EC_KEY(EC_KEY *ec_key);
size_t compute_ecdh_secret(EC_KEY *own_key, EC_KEY *peer_key, unsigned char **secret) ;
void derive_key_with_hkdf(const unsigned char *secret, size_t secret_len, unsigned char *out_key, size_t out_len, const char *info);
void dbl(u8 *pad);
void xor(u8 *a, const u8 *b);
static void xorend(u8 *a, int alen, const u8 *b, int blen);
static void pad_block(u8 *pad, const u8 *addr, size_t len);
int omac1_aes_vector(const u8 *key, size_t key_len, size_t num_elem, const u8 *addr[], size_t *len, u8 *mac);
int aes_s2v(const u8 *key, size_t key_len, size_t num_elem, const u8 *addr[], size_t *len, u8 *mac);
int aes_ctr_encrypt(const u8 *key, size_t key_len, const u8 *nonce, u8 *data, size_t data_len);
int aes_siv_encrypt(const u8 *key, size_t key_len, const u8 *pw, size_t pwlen,
                    size_t num_elem, const u8 *addr[], const size_t *len, u8 *out);
int aes_siv_decrypt(const u8 *key, size_t key_len,
		    const u8 *iv_crypt, size_t iv_c_len,
		    size_t num_elem, const u8 *addr[], const size_t *len,
		    u8 *out);
int sha256_vector(size_t num_elem, const u8 *addr[], const size_t *len,
            u8 *mac);
int hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
		       const u8 *addr[], const size_t *len, u8 *mac);				
static int digest_vector(mbedtls_md_type_t md_type, size_t num_elem,
                         const u8 *addr[], const size_t *len, u8 *mac);
int hmac_sha256_kdf(const u8 *secret, size_t secret_len,
		    const char *label, const u8 *seed, size_t seed_len,
		    u8 *out, size_t outlen);





enum dpp_attribute_id {
	DPP_ATTR_STATUS = 0x1000,
	DPP_ATTR_I_BOOTSTRAP_KEY_HASH = 0x1001,
	DPP_ATTR_R_BOOTSTRAP_KEY_HASH = 0x1002,
	DPP_ATTR_I_PROTOCOL_KEY = 0x1003,
	DPP_ATTR_WRAPPED_DATA = 0x1004,
	DPP_ATTR_I_NONCE = 0x1005,
	DPP_ATTR_I_CAPABILITIES = 0x1006,
	DPP_ATTR_R_NONCE = 0x1007,
	DPP_ATTR_R_CAPABILITIES = 0x1008,
	DPP_ATTR_R_PROTOCOL_KEY = 0x1009,
	DPP_ATTR_I_AUTH_TAG = 0x100A,
	DPP_ATTR_R_AUTH_TAG = 0x100B,
	DPP_ATTR_CONFIG_OBJ = 0x100C,
	DPP_ATTR_CONNECTOR = 0x100D,
	DPP_ATTR_CONFIG_ATTR_OBJ = 0x100E,
	DPP_ATTR_BOOTSTRAP_KEY = 0x100F,
	DPP_ATTR_OWN_NET_NK_HASH = 0x1011,
	DPP_ATTR_FINITE_CYCLIC_GROUP = 0x1012,
	DPP_ATTR_ENCRYPTED_KEY = 0x1013,
	DPP_ATTR_ENROLLEE_NONCE = 0x1014,
	DPP_ATTR_CODE_IDENTIFIER = 0x1015,
	DPP_ATTR_TRANSACTION_ID = 0x1016,
	DPP_ATTR_BOOTSTRAP_INFO = 0x1017,
	DPP_ATTR_CHANNEL = 0x1018,
	DPP_ATTR_PROTOCOL_VERSION = 0x1019,
	DPP_ATTR_ENVELOPED_DATA = 0x101A,
	DPP_ATTR_SEND_CONN_STATUS = 0x101B,
	DPP_ATTR_CONN_STATUS = 0x101C,
};

#endif  // _REQUESTFRAME_H_