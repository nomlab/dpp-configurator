#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include "mbedtls/cmac.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "crypto.h"

#define u8 unsigned char
#define MBEDTLS_AES_BLOCK_SIZE 16
#define SHA256_MAC_LEN 32
static const u8 zero[AES_BLOCK_SIZE];
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
static const char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


void forced_memzero(void *ptr, size_t len)
{
    mbedtls_platform_zeroize(ptr, len);
}

void put_le16(uint16_t data, uint8_t *buffer) {
    buffer[0] = (uint8_t)(data & 0xFF);       // 低位バイト
    buffer[1] = (uint8_t)((data >> 8) & 0xFF); // 高位バイト
}

void *memdup(const void *src, size_t len) {
    void *dst = malloc(len);
    if (dst)
        memcpy(dst, src, len);
    return dst;
}

// エラーハンドリング関数
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

unsigned char * base64_gen_decode(const char *src, size_t len,
					 size_t *out_len, const char *table)
{
	unsigned char dtable[256], *out, *pos, block[4], tmp;
	size_t i, count, olen;
	int pad = 0;
	size_t extra_pad;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[(unsigned char) table[i]] = (unsigned char) i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[(unsigned char) src[i]] != 0x80)
			count++;
	}

	if (count == 0)
		return NULL;
	extra_pad = (4 - count % 4) % 4;

	olen = (count + extra_pad) / 4 * 3;
	pos = out = malloc(olen);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len + extra_pad; i++) {
		unsigned char val;

		if (i >= len)
			val = '=';
		else
			val = src[i];
		tmp = dtable[val];
		if (tmp == 0x80)
			continue;

		if (val == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					free(out);
					return NULL;
				}
				break;
			}
		}
	}

	*out_len = pos - out;
	return out;
}
u8* create_ec_key_from_der(const unsigned char* der_data, size_t der_len, size_t *key_len){
    const u8 *p = der_data;
    EC_KEY *ec_key = d2i_EC_PUBKEY(NULL, &p, der_len);
    if (ec_key == NULL){
        handleErrors();
    }

    const EC_POINT *pub_key_point = EC_KEY_get0_public_key(ec_key);
    if(pub_key_point == NULL){
        handleErrors();
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);

    u8 *key = NULL;
    *key_len = EC_POINT_point2buf(
        group, pub_key_point, POINT_CONVERSION_UNCOMPRESSED, &key, NULL);
    if(key == NULL){
        handleErrors();
    }
    return key;
}

// ECDH鍵ペアの生成関数
EVP_PKEY* generate_ec_key(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL) {
        handleErrors();
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        handleErrors();
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) { // P-256
        handleErrors();
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        handleErrors();
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}
// バイト列として与えられた秘密鍵を EC_KEY に変換する関数
EC_KEY *create_ec_key_from_private_key_bytes(const unsigned char *priv_key_bytes, size_t priv_key_len) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_key == NULL) {
        handleErrors();
    }

    BIGNUM *priv_key = BN_bin2bn(priv_key_bytes, priv_key_len, NULL);
    if (priv_key == NULL) {
        handleErrors();
    }

    if (EC_KEY_set_private_key(ec_key, priv_key) != 1) {
        handleErrors();
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub_key_point = EC_POINT_new(group);
    if (pub_key_point == NULL) {
        handleErrors();
    }
    if (EC_POINT_mul(group, pub_key_point, priv_key, NULL, NULL, NULL) != 1) {
        handleErrors();
    }
    if (EC_KEY_set_public_key(ec_key, pub_key_point) != 1) {
        handleErrors();
    }
    EC_POINT_free(pub_key_point);
    BN_free(priv_key);
    return ec_key;
}

// バイト列として与えられた公開鍵を EC_KEY に変換する関数
EC_KEY *convert_bytes_to_EC_KEY(const unsigned char *pub_key_bytes, size_t pub_key_len) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_key == NULL) {
        handleErrors();
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub_key = EC_POINT_new(group);
    if (pub_key == NULL) {
        handleErrors();
    }

    if (EC_POINT_oct2point(group, pub_key, pub_key_bytes, pub_key_len, NULL) != 1) {
        handleErrors();
    }

    if (EC_KEY_set_public_key(ec_key, pub_key) != 1) {
        handleErrors();
    }

    EC_POINT_free(pub_key);
    return ec_key;
}

// EC_KEY 構造体から公開鍵を取得してバイト列にエンコードする関数
int encode_ec_public_key(EC_KEY *ec_key, unsigned char **out_pub_key, size_t *out_pub_key_len) {
    const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    if (pub_key == NULL || group == NULL) {
        handleErrors();
        return 0;
    }

    size_t key_len = EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (key_len == 0) {
        handleErrors();
        return 0;
    }

    *out_pub_key = (unsigned char *)malloc(key_len);
    if (*out_pub_key == NULL) {
        handleErrors();
        return 0;
    }

    if (EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, *out_pub_key, key_len, NULL) != key_len) {
        handleErrors();
        free(*out_pub_key);
        return 0;
    }

    *out_pub_key_len = key_len;
    return 1;
}
// 公開鍵のハッシュを計算する関数
int calculate_public_key_hash(EC_KEY *eckey, unsigned char *hash) {
    // 公開鍵をDER形式に変換
    int keylen = i2d_EC_PUBKEY(eckey, NULL);
    if (keylen < 0) {
        fprintf(stderr, "i2d_EC_PUBKEY failed\n");
        return 1;
    }

    unsigned char *der = (unsigned char *)OPENSSL_malloc(keylen);
    if (der == NULL) {
        fprintf(stderr, "OPENSSL_malloc failed\n");
        return 1;
    }

    unsigned char *p = der;
    if (i2d_EC_PUBKEY(eckey, &p) < 0) {
        fprintf(stderr, "i2d_EC_PUBKEY failed\n");
        OPENSSL_free(der);
        return 1;
    }

    // SHA-256でハッシュを計算
    SHA256(der, keylen, hash);

    // リソースの解放
    OPENSSL_free(der);

    return 0;
}

// テスト用の表示関数 (EC_KEY を直接与える)
void print_EC_KEY(EC_KEY *ec_key){
if (ec_key == NULL) {
        printf("No EC_KEY in EVP_PKEY.\n");
        return;
    }

    const BIGNUM *priv_key = EC_KEY_get0_private_key(ec_key);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);

    if (priv_key) {
        unsigned char *priv_key_bin = OPENSSL_malloc(BN_num_bytes(priv_key));
        if (priv_key_bin == NULL) {
            handleErrors();
        }
        int priv_key_len = BN_bn2bin(priv_key, priv_key_bin);
        printf("Private key %d oct :", priv_key_len);
        for (int i = 0; i < priv_key_len; i++) {
            printf("%02x", priv_key_bin[i]);
        }
        printf("\n");
        OPENSSL_free(priv_key_bin);
    } else {
        printf("No private key\n");
    }

    if (pub_key && group) {
        unsigned char *pub_key_bin = OPENSSL_malloc(EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL));
        if (pub_key_bin == NULL) {
            handleErrors();
        }
        int pub_key_len = EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, pub_key_bin, EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL), NULL);
        printf("Public key: %d oct :", pub_key_len);
        for (int i = 0; i < pub_key_len; i++) {
            printf("%02x", pub_key_bin[i]);
        }
        printf("\n");
        OPENSSL_free(pub_key_bin);
    } else {
        printf("No public key\n");
    }
}

// 共通秘密鍵の計算関数
size_t compute_ecdh_secret(EC_KEY *own_key, EC_KEY *peer_key, unsigned char **secret) {
    // EVP_PKEYコンテキストの初期化
    EVP_PKEY *own_pkey = EVP_PKEY_new();
    if (own_pkey == NULL) {
        handleErrors();
    }
    if (EVP_PKEY_set1_EC_KEY(own_pkey, own_key) <= 0) {
        handleErrors();
    }

    EVP_PKEY *peer_pkey = EVP_PKEY_new();
    if (peer_pkey == NULL) {
        handleErrors();
    }
    if (EVP_PKEY_set1_EC_KEY(peer_pkey, peer_key) <= 0) {
        handleErrors();
    }

    // ECDHコンテキストの初期化
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(own_pkey, NULL);
    if (ctx == NULL) {
        handleErrors();
    }

    // 秘密鍵の導出初期化
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        handleErrors();
    }

    // ピア鍵の設定
    if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
        handleErrors();
    }

    // 秘密鍵の長さを計算
    size_t secret_len;
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
        handleErrors();
    }

    // 秘密鍵を格納するためのメモリを確保
    *secret = OPENSSL_malloc(secret_len);
    if (*secret == NULL) {
        handleErrors();
    }

    // 秘密鍵の導出
    if (EVP_PKEY_derive(ctx, *secret, &secret_len) <= 0) {
        handleErrors();
    }

    // コンテキストの解放
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(own_pkey);
    EVP_PKEY_free(peer_pkey);

    return secret_len;
}

// HKDFを使用した鍵導出関数
void derive_key_with_hkdf(const unsigned char *secret, size_t secret_len, unsigned char *out_key, size_t out_len, const char *info) {
    //const unsigned char info[] = "first intermediate key";
    size_t info_len = strlen((const char*)info);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        handleErrors();
    }

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        handleErrors();
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        handleErrors();
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0) <= 0) {
        handleErrors();
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secret_len) <= 0) {
        handleErrors();
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
        handleErrors();
    }

    if (EVP_PKEY_derive(pctx, out_key, &out_len) <= 0) {
        handleErrors();
    }

    EVP_PKEY_CTX_free(pctx);
}

// AES-S2V関数
void dbl(u8 *pad) {
    int i, carry;

    carry = pad[0] & 0x80;
    for ( i = 0; i < AES_BLOCK_SIZE -1; i++)
        pad[i] = (pad[i] << 1) | (pad[i + 1]  >> 7);
    pad[AES_BLOCK_SIZE - 1] <<= 1 ;
    if(carry)
        pad[AES_BLOCK_SIZE - 1] ^= 0x87;
}

void xor(u8 *a, const u8 *b) {
    int i;
    for (i = 0; i < AES_BLOCK_SIZE; i++)
        *a++ ^= *b++;
}

static void xorend(u8 *a, int alen, const u8 *b, int blen) {
    int i;

    if (alen < blen)
        return;
    for ( i = 0; i < blen; i++)
        a[alen - blen + i] ^= b[i];
}

static void pad_block(u8 *pad, const u8 *addr, size_t len) {
    memset(pad, 0, AES_BLOCK_SIZE);
    memcpy(pad, addr, len);
    if (len < AES_BLOCK_SIZE)
        pad[len] = 0x80;
}

int omac1_aes_vector(const u8 *key, size_t key_len, size_t num_elem, const u8 *addr[], size_t *len, u8 *mac) 
    {
    const mbedtls_cipher_info_t *cipher_info;
    int i, ret = 0;
    mbedtls_cipher_type_t cipher_type;
    mbedtls_cipher_context_t ctx;

    switch (key_len) {
    case 16:
        cipher_type = MBEDTLS_CIPHER_AES_128_ECB;
        break;
    case 24:
        cipher_type = MBEDTLS_CIPHER_AES_192_ECB;
        break;
    case 32:
        cipher_type = MBEDTLS_CIPHER_AES_256_ECB;
        break;
    default:
        cipher_type = MBEDTLS_CIPHER_NONE;
        break;
    }
    cipher_info = mbedtls_cipher_info_from_type(cipher_type);
    if (cipher_info == NULL) {
        /* Failing at this point must be due to a build issue */
        ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        goto cleanup;
    }

    if (key == NULL ||  mac == NULL) {
        return -1;
    }

    mbedtls_cipher_init(&ctx);

    ret = mbedtls_cipher_setup(&ctx, cipher_info);
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_cipher_cmac_starts(&ctx, key, key_len * 8);
    if (ret != 0) {
        goto cleanup;
    }

    for (i = 0 ; i < num_elem; i++) {
        ret = mbedtls_cipher_cmac_update(&ctx, addr[i], len[i]);
        if (ret != 0) {
            goto cleanup;
        }
    }

    ret = mbedtls_cipher_cmac_finish(&ctx, mac);
cleanup:
    mbedtls_cipher_free(&ctx);
    return (ret);
}

int aes_s2v(const u8 *key, size_t key_len, size_t num_elem, const u8 *addr[], size_t *len, u8 *mac) {
    //printf("called aes_s2v\n"); =>0k
    u8 tmp[AES_BLOCK_SIZE], tmp2[AES_BLOCK_SIZE];
    u8 *buf = NULL;
    int ret;
    size_t i;
    const u8 *data[1];
    size_t data_len[1];
    
    if (!num_elem) {
        memcpy(tmp, zero, sizeof(zero));
        tmp[AES_BLOCK_SIZE - 1] = 1;
        data[0] = tmp;
        data_len[0] = sizeof(tmp);
        return omac1_aes_vector(key, key_len, 1, data, data_len, mac);
    }
    //return 0; =>ok
    //printf("called\n"); =>0k
    data[0] = zero;
    data_len[0] = sizeof(zero);
    ret = omac1_aes_vector(key, key_len, 1, data, data_len, tmp);
    //return 0; => ok
    if (ret)
        return ret;
    //printf("called\n"); =>0k 
    for (i = 0; i < num_elem - 1; i++) {
        ret = omac1_aes_vector(key, key_len, 1, &addr[i], &len[i], tmp2); // => not work?
        if (ret)
            return ret;

        dbl(tmp);
        xor(tmp, tmp2);
    }
    //return 0; => not work
    //printf("called\n"); =>0k
    if (len[i] >= AES_BLOCK_SIZE) {
        buf = memdup(addr[i], len[i]);
        if (!buf)
            return -1;
        //printf("called\n"); =>0k
        xorend(buf, len[i], tmp, AES_BLOCK_SIZE);
        data[0] = buf;
        //printf("called\n"); =>ok
        ret = omac1_aes_vector(key, key_len, 1, data, &len[i], mac);
        //printf("called\n"); =>ok
        free(buf);
        //printf("called\n"); =>ok
        return ret;
    }
    dbl(tmp);
    pad_block(tmp2, addr[i], len[i]);
    xor(tmp, tmp2);

    data[0] = tmp;
    data_len[0] = sizeof(tmp);
    return omac1_aes_vector(key, key_len, 1, data, data_len, mac);
}
int aes_ctr_encrypt(const u8 *key, size_t key_len, const u8 *nonce, u8 *data, size_t data_len) {
    int ret;
    mbedtls_aes_context ctx;
    uint8_t stream_brock[MBEDTLS_AES_BLOCK_SIZE];
    size_t offset = 0;

    mbedtls_aes_init(&ctx);
    ret = mbedtls_aes_setkey_enc(&ctx, key, key_len * 8);
    if (ret < 0) {
        mbedtls_aes_free(&ctx);
        return ret;
    }
    ret = mbedtls_aes_crypt_ctr(&ctx, data_len, &offset, (u8 *)nonce, stream_brock, data, data);
    mbedtls_aes_free(&ctx);
    return ret;   

}
// AES-SIV暗号化関数
int aes_siv_encrypt(const u8 *key, size_t key_len, const u8 *pw, size_t pwlen,
                    size_t num_elem, const u8 *addr[], const size_t *len, u8 *out) {
    
    //printf("called aes_siv_encrypt\n"); =>0k
    const u8 *_addr[6];
    size_t _len[6];
    const u8 *k1, *k2;
    u8 v[AES_BLOCK_SIZE];
    size_t i;
    u8 *iv, *crypt_pw;

    if (num_elem > sizeof(_addr) / sizeof(_addr[0]) - 1 || (key_len != 32 && key_len != 48 && key_len != 64))
        return -1;

    key_len /= 2;
    k1 = key;
    k2 = key + key_len;

    //printf("called\n"); =>0k 
    for (i = 0; i < num_elem; i++) {
        _addr[i] = addr[i];
        _len[i] = len[i];
    }
    _addr[num_elem] = pw;
    _len[num_elem] = pwlen;

    //printf("called\n"); => ok 
    if (aes_s2v(k1, key_len, num_elem + 1, _addr, _len, v))
        return -1;
    //printf("called\n"); =>not work
    iv = out;
    crypt_pw = out + AES_BLOCK_SIZE;
    memcpy(iv, v, AES_BLOCK_SIZE);
    memcpy(crypt_pw, pw, pwlen);

    

    // Zero out 63rd and 31st bits of ctr (from right)
    v[8] &= 0x7f;
    v[12] &= 0x7f;

    return aes_ctr_encrypt(k2, key_len, v, crypt_pw, pwlen);
}
int aes_siv_decrypt(const u8 *key, size_t key_len,
		    const u8 *iv_crypt, size_t iv_c_len,
		    size_t num_elem, const u8 *addr[], const size_t *len,
		    u8 *out)
{
	const u8 *_addr[6];
	size_t _len[6];
	const u8 *k1, *k2;
	size_t crypt_len;
	size_t i;
	int ret;
	u8 iv[AES_BLOCK_SIZE];
	u8 check[AES_BLOCK_SIZE];

	if (iv_c_len < AES_BLOCK_SIZE || num_elem > ARRAY_SIZE(_addr) - 1 ||
	    (key_len != 32 && key_len != 48 && key_len != 64))
		return -1;
	crypt_len = iv_c_len - AES_BLOCK_SIZE;
	key_len /= 2;
	k1 = key;
	k2 = key + key_len;

	for (i = 0; i < num_elem; i++) {
		_addr[i] = addr[i];
		_len[i] = len[i];
	}
	_addr[num_elem] = out;
	_len[num_elem] = crypt_len;

	memcpy(iv, iv_crypt, AES_BLOCK_SIZE);
	memcpy(out, iv_crypt + AES_BLOCK_SIZE, crypt_len);

	iv[8] &= 0x7f;
	iv[12] &= 0x7f;

	ret = aes_ctr_encrypt(k2, key_len, iv, out, crypt_len);
	if (ret)
		return ret;

	ret = aes_s2v(k1, key_len, num_elem + 1, _addr, _len, check);
	if (ret)
		return ret;
	if (memcmp(check, iv_crypt, AES_BLOCK_SIZE) == 0)
		return 0;

	return -1;
}
static int digest_vector(mbedtls_md_type_t md_type, size_t num_elem,
                         const u8 *addr[], const size_t *len, u8 *mac)
{
    size_t i;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;
    int ret;

    mbedtls_md_init(&md_ctx);

    md_info = mbedtls_md_info_from_type(md_type);
    if (!md_info) {
        printf("mbedtls_md_info_from_type() failed");
        return -1;
    }

    ret = mbedtls_md_setup(&md_ctx, md_info, 0);
    if (ret != 0) {
        printf("mbedtls_md_setup() returned error");
        goto cleanup;
    }

    ret = mbedtls_md_starts(&md_ctx);
    if (ret != 0) {
        printf("mbedtls_md_starts returned error");
        goto cleanup;
    }

    for (i = 0; i < num_elem; i++) {
        ret = mbedtls_md_update(&md_ctx, addr[i], len[i]);
        if (ret != 0) {
            printf("mbedtls_md_update ret=%d", ret);
            goto cleanup;
        }
    }

    ret = mbedtls_md_finish(&md_ctx, mac);
cleanup:
    mbedtls_md_free(&md_ctx);

    return ret;

}
int sha256_vector(size_t num_elem, const u8 *addr[], const size_t *len,
                  u8 *mac)
{
    return digest_vector(4, num_elem, addr, len, mac);
}

int hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
		       const u8 *addr[], const size_t *len, u8 *mac)
{
	unsigned char k_pad[64]; /* padding - key XORd with ipad/opad */
	unsigned char tk[32];
	const u8 *_addr[11];
	size_t _len[11], i;

	if (num_elem > 10) {
		/*
		 * Fixed limit on the number of fragments to avoid having to
		 * allocate memory (which could fail).
		 */
		return -1;
	}

        /* if key is longer than 64 bytes reset it to key = SHA256(key) */
        if (key_len > 64) {
		if (sha256_vector(1, &key, &key_len, tk) < 0)
			return -1;
		key = tk;
		key_len = 32;
        }

	/* the HMAC_SHA256 transform looks like:
	 *
	 * SHA256(K XOR opad, SHA256(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected */

	/* start out by storing key in ipad */
	memset(k_pad, 0, sizeof(k_pad));
	memcpy(k_pad, key, key_len);
	/* XOR key with ipad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x36;

	/* perform inner SHA256 */
	_addr[0] = k_pad;
	_len[0] = 64;
	for (i = 0; i < num_elem; i++) {
		_addr[i + 1] = addr[i];
		_len[i + 1] = len[i];
	}
	if (sha256_vector(1 + num_elem, _addr, _len, mac) < 0)
		return -1;

	memset(k_pad, 0, sizeof(k_pad));
	memcpy(k_pad, key, key_len);
	/* XOR key with opad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x5c;

	/* perform outer SHA256 */
	_addr[0] = k_pad;
	_len[0] = 64;
	_addr[1] = mac;
	_len[1] = 32;
	return sha256_vector(2, _addr, _len, mac);
}
int hmac_sha256_kdf(const u8 *secret, size_t secret_len,
		    const char *label, const u8 *seed, size_t seed_len,
		    u8 *out, size_t outlen)
{
	u8 T[SHA256_MAC_LEN];
	u8 iter = 1;
	const unsigned char *addr[4];
	size_t len[4];
	size_t pos, clen;

	addr[0] = T;
	len[0] = SHA256_MAC_LEN;
	if (label) {
		addr[1] = (const unsigned char *) label;
		len[1] = strlen(label) + 1;
	} else {
		addr[1] = (const u8 *) "";
		len[1] = 0;
	}
	addr[2] = seed;
	len[2] = seed_len;
	addr[3] = &iter;
	len[3] = 1;


	if (hmac_sha256_vector(secret, secret_len, 3, &addr[1], &len[1], T) < 0)
		return -1;


	pos = 0;
	for (;;) {
		clen = outlen - pos;
		if (clen > SHA256_MAC_LEN)
			clen = SHA256_MAC_LEN;
		memcpy(out + pos, T, clen);
        printf("hi\n");
		pos += clen;

		if (pos == outlen)
			break;

		if (iter == 255) {
			memset(out, 0, outlen);
			forced_memzero(T, SHA256_MAC_LEN);
			return -1;
		}
		iter++;

		if (hmac_sha256_vector(secret, secret_len, 4, addr, len, T) < 0)
		{
			memset(out, 0, outlen);
			forced_memzero(T, SHA256_MAC_LEN);
			return -1;
		}
	}
	forced_memzero(T, SHA256_MAC_LEN);
	return 0;
}


