/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "config.h"
#include "psk.h"
#include "log-private.h"
#include "crypto-private.h"
#include <string.h>

#if HAVE_MBEDTLS
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/gcm.h"
#elif HAVE_NETTLE
#include <nettle/pbkdf2.h>
#include <nettle/aes.h>
#include <nettle/ctr.h>
#include <nettle/hmac.h>
#include <nettle/gcm.h>
#include <nettle/memops.h>
#elif defined(LINUX_CRYPTO)
#include "linux-crypto.h"
#endif
#if !HAVE_MBEDTLS
#include "fastpbkdf2.h"
#endif

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

#include <stdint.h>

//TODO: handle failures?
int _librist_crypto_psk_rist_key_init(struct rist_key *key, uint32_t key_size, uint32_t rotation, const char *password, bool odd)
{
	key->password_len = strnlen(password, sizeof(key->password) - 1);
	memcpy(key->password, password, key->password_len);
	key->password[key->password_len] = '\0';
	key->key_size = key_size;
	key->key_rotation = rotation;
#if HAVE_MBEDTLS
	mbedtls_aes_init(&key->mbedtls_aes_ctx);
#elif HAVE_NETTLE
	memset(&key->nettle_ctx, 0, sizeof(key->nettle_ctx));
#elif defined(LINUX_CRYPTO)
	linux_crypto_init(&key->linux_crypto_ctx);
#endif
	key->odd = odd;
	return 0;
}

int _librist_crypto_psk_rist_key_destroy(struct rist_key *key)
{
    if (key->key_size) {
#if HAVE_MBEDTLS
	    mbedtls_aes_free(&key->mbedtls_aes_ctx);
#elif HAVE_NETTLE
	//nothing to do here
#elif defined(LINUX_CRYPTO)
	    linux_crypto_free(&key->linux_crypto_ctx);
#endif
    }
	return 0;
}

int _librist_crypto_psk_rist_key_clone(struct rist_key *key_in, struct rist_key *key_out)
{
	key_out->password_len = key_in->password_len;
	memcpy(key_out->password, key_in->password, key_in->password_len);
	key_out->password[key_out->password_len] = '\0';
    key_out->key_size = key_in->key_size;
    key_out->key_rotation = key_in->key_rotation;
#if HAVE_MBEDTLS
	mbedtls_aes_init(&key_out->mbedtls_aes_ctx);
#elif HAVE_NETTLE
    memset(&key_out->nettle_ctx, 0, sizeof(key_out->nettle_ctx));
#elif defined(LINUX_CRYPTO)
	linux_crypto_init(&key_out->linux_crypto_ctx);
#endif
	key_out->odd = key_in->odd;
	return 0;
}

static void _librist_crypto_aes_key(struct rist_key *key)
{
    uint8_t aes_key[256 / 8];
#if HAVE_MBEDTLS
    mbedtls_md_context_t sha_ctx;
    const mbedtls_md_info_t *info_sha;
    int ret = -1;
    mbedtls_md_init(&sha_ctx);
    info_sha = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info_sha == NULL)
        goto fail;

    ret = mbedtls_md_setup(&sha_ctx, info_sha, 1);
    if (ret != 0)
        goto fail;

    ret = mbedtls_pkcs5_pbkdf2_hmac(
        &sha_ctx, (const unsigned char *)key->password, key->password_len,
        key->gre_nonce, sizeof(key->gre_nonce),
        RIST_PBKDF2_HMAC_SHA256_ITERATIONS, key->key_size / 8, aes_key);
    if (ret != 0)
        goto fail;
    mbedtls_md_free(&sha_ctx);
#elif HAVE_NETTLE
    nettle_pbkdf2_hmac_sha256(key->password_len,(const uint8_t*)key->password,
							  RIST_PBKDF2_HMAC_SHA256_ITERATIONS,
							  sizeof(key->gre_nonce), key->gre_nonce,
							  key->key_size/8, aes_key);
#else
    fastpbkdf2_hmac_sha256(
            (const void *) key->password, key->password_len,
            (const void *) key->gre_nonce, sizeof(key->gre_nonce),
            RIST_PBKDF2_HMAC_SHA256_ITERATIONS,
            aes_key, key->key_size / 8);
#endif


#if HAVE_MBEDTLS
    mbedtls_aes_setkey_enc(&key->mbedtls_aes_ctx, aes_key, key->key_size);
#elif HAVE_NETTLE
	switch(key->key_size) {
	case 256:
        nettle_aes256_set_encrypt_key(&key->nettle_ctx.u.ctx256, aes_key);
        break;
	case 192:
        nettle_aes192_set_encrypt_key(&key->nettle_ctx.u.ctx192, aes_key);
        break;
	case 128:
		RIST_FALLTHROUGH;
	default:
		nettle_aes128_set_encrypt_key(&key->nettle_ctx.u.ctx128, aes_key);
    }
#elif defined(LINUX_CRYPTO)
    if (key->linux_crypto_ctx)
		linux_crypto_set_key(aes_key, key->key_size / 8, key->linux_crypto_ctx);
    else
        aes_key_setup(aes_key, key->aes_key_sched, key->key_size);
#else
    aes_key_setup(aes_key, key->aes_key_sched, key->key_size);
#endif
    key->used_times = 0;
    return;
#if HAVE_MBEDTLS
fail:
    mbedtls_md_free(&sha_ctx);
    /* Leave any prior key install in place but force the lockout flag so we
     * don't run AES-CTR with whatever happened to be on the stack. */
    key->bad_decryption = true;
    return;
#endif
}

//This doesn't really belong here (not PSK related), but since all other crypto interop stuff is here it goes in here..
void _librist_crypto_aes_ctr(const uint8_t key[], int key_size, uint8_t iv[], const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len) {
#if HAVE_MBEDTLS
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_enc(&ctx, key, key_size);
	uint8_t stream_block[AES_BLOCK_SIZE] = {0};
	size_t nc_off = 0;
	mbedtls_aes_crypt_ctr(&ctx, payload_len, &nc_off, iv, stream_block, inbuf, outbuf);
	mbedtls_aes_free(&ctx);
#elif HAVE_NETTLE
    struct aes_ctx aes_ctx;
    memset(&aes_ctx, 0, sizeof(aes_ctx));
    nettle_cipher_func *f;
    switch (key_size) {
    case 256:
		nettle_aes256_set_encrypt_key(&aes_ctx.u.ctx256, key);
		f = (nettle_cipher_func *)nettle_aes256_encrypt;
		break;
	case 192:
		nettle_aes192_set_encrypt_key(&aes_ctx.u.ctx192, key);
		f = (nettle_cipher_func *)nettle_aes192_encrypt;
		break;
	case 128:
		nettle_aes128_set_encrypt_key(&aes_ctx.u.ctx128, key);
		f = (nettle_cipher_func *)nettle_aes128_encrypt;
		break;
	default:
		return;
	}
	nettle_ctr_crypt(&aes_ctx.u, f, AES_BLOCK_SIZE, iv, payload_len, outbuf, inbuf);
#else
    uint32_t aes_key_sched[60];
    aes_key_setup(key, aes_key_sched, key_size);
    aes_decrypt_ctr(inbuf, payload_len, outbuf, aes_key_sched, key_size, iv);
#endif
}

/* EAP SHA256-SRP6a Version 4 crypto primitives.
 *
 * These back the v4 authenticated passphrase channel: HKDF-Expand-SHA256 to
 * split the SRP session key K into per-direction keys, and AES-256-GCM to carry
 * the passphrase with integrity + authenticity. They live here alongside the
 * other AES interop helpers. AEAD/HMAC are only available with a real crypto
 * backend (mbedTLS or Nettle); the built-in fallback returns -1 so the caller
 * declines v4 and negotiates down to the v3 AES-CTR channel. */

/* RFC 5869 §2.3 HKDF-Expand with SHA-256. PRK is used directly as the HMAC key
 * (K is already a uniformly random 256-bit value, so Extract is unnecessary).
 * Returns 0 on success, -1 on error / backend unavailable. */
int _librist_crypto_hkdf_expand_sha256(const uint8_t *prk, size_t prk_len,
                                       const uint8_t *info, size_t info_len,
                                       uint8_t *okm, size_t okm_len)
{
    const size_t hash_len = 32;
    if (okm_len == 0 || okm_len > 255 * hash_len)
        return -1;
#if HAVE_MBEDTLS
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL)
        return -1;
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int rc = -1;
    if (mbedtls_md_setup(&ctx, md, 1) != 0)
        goto done;
    uint8_t t[32];
    size_t t_len = 0;
    size_t done_len = 0;
    uint8_t counter = 0;
    while (done_len < okm_len) {
        counter++;
        if (mbedtls_md_hmac_starts(&ctx, prk, prk_len) != 0) goto done;
        if (t_len && mbedtls_md_hmac_update(&ctx, t, t_len) != 0) goto done;
        if (info_len && mbedtls_md_hmac_update(&ctx, info, info_len) != 0) goto done;
        if (mbedtls_md_hmac_update(&ctx, &counter, 1) != 0) goto done;
        if (mbedtls_md_hmac_finish(&ctx, t) != 0) goto done;
        t_len = hash_len;
        size_t n = okm_len - done_len < hash_len ? okm_len - done_len : hash_len;
        memcpy(okm + done_len, t, n);
        done_len += n;
    }
    rc = 0;
done:
    mbedtls_md_free(&ctx);
    if (rc != 0)
        memset(okm, 0, okm_len);
    return rc;
#elif HAVE_NETTLE
    struct hmac_sha256_ctx ctx;
    hmac_sha256_set_key(&ctx, prk_len, prk);
    uint8_t t[32];
    size_t t_len = 0;
    size_t done_len = 0;
    uint8_t counter = 0;
    while (done_len < okm_len) {
        counter++;
        if (t_len) hmac_sha256_update(&ctx, t_len, t);
        if (info_len) hmac_sha256_update(&ctx, info_len, info);
        hmac_sha256_update(&ctx, 1, &counter);
        hmac_sha256_digest(&ctx, hash_len, t); /* resets to post-set-key state */
        t_len = hash_len;
        size_t n = okm_len - done_len < hash_len ? okm_len - done_len : hash_len;
        memcpy(okm + done_len, t, n);
        done_len += n;
    }
    return 0;
#else
    (void)prk; (void)prk_len; (void)info; (void)info_len;
    memset(okm, 0, okm_len);
    return -1;
#endif
}

/* AES-256-GCM encrypt. key is 32 octets, iv is iv_len octets (12 for v4),
 * tag_len is 16. Returns 0 on success, -1 on error / backend unavailable. */
int _librist_crypto_aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                                    const uint8_t *aad, size_t aad_len,
                                    const uint8_t *pt, size_t pt_len,
                                    uint8_t *ct, uint8_t *tag, size_t tag_len)
{
#if HAVE_MBEDTLS
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = -1;
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) != 0)
        goto done;
    if (mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, pt_len, iv, iv_len,
                                  aad, aad_len, pt, ct, tag_len, tag) != 0)
        goto done;
    rc = 0;
done:
    mbedtls_gcm_free(&ctx);
    return rc;
#elif HAVE_NETTLE
    struct gcm_aes256_ctx ctx;
    gcm_aes256_set_key(&ctx, key);
    gcm_aes256_set_iv(&ctx, iv_len, iv);
    if (aad_len)
        gcm_aes256_update(&ctx, aad_len, aad);
    gcm_aes256_encrypt(&ctx, pt_len, ct, pt);
    gcm_aes256_digest(&ctx, tag_len, tag);
    return 0;
#else
    (void)key; (void)iv; (void)iv_len; (void)aad; (void)aad_len;
    (void)pt; (void)pt_len; (void)ct; (void)tag; (void)tag_len;
    return -1;
#endif
}

/* AES-256-GCM decrypt with tag verification. Returns 0 only if the tag is valid;
 * -1 on tag failure / error / backend unavailable. On any failure the plaintext
 * buffer is zeroed so a caller can never act on unverified output. */
int _librist_crypto_aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                                    const uint8_t *aad, size_t aad_len,
                                    const uint8_t *ct, size_t ct_len,
                                    const uint8_t *tag, size_t tag_len,
                                    uint8_t *pt)
{
#if HAVE_MBEDTLS
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = -1;
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) != 0)
        goto done;
    if (mbedtls_gcm_auth_decrypt(&ctx, ct_len, iv, iv_len, aad, aad_len,
                                 tag, tag_len, ct, pt) != 0)
        goto done;
    rc = 0;
done:
    mbedtls_gcm_free(&ctx);
    if (rc != 0 && ct_len)
        memset(pt, 0, ct_len);
    return rc;
#elif HAVE_NETTLE
    struct gcm_aes256_ctx ctx;
    uint8_t local_tag[16];
    if (tag_len > sizeof(local_tag))
        return -1;
    gcm_aes256_set_key(&ctx, key);
    gcm_aes256_set_iv(&ctx, iv_len, iv);
    if (aad_len)
        gcm_aes256_update(&ctx, aad_len, aad);
    gcm_aes256_decrypt(&ctx, ct_len, pt, ct);
    gcm_aes256_digest(&ctx, tag_len, local_tag);
    /* nettle memeql_sec is constant-time; returns 1 when equal. */
    if (memeql_sec(local_tag, tag, tag_len) != 1) {
        if (ct_len)
            memset(pt, 0, ct_len);
        return -1;
    }
    return 0;
#else
    (void)key; (void)iv; (void)iv_len; (void)aad; (void)aad_len;
    (void)ct; (void)tag; (void)tag_len;
    if (ct_len)
        memset(pt, 0, ct_len);
    return -1;
#endif
}

static void _librist_crypto_psk_aes_ctr(struct rist_key *key, const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len)
{
#if HAVE_MBEDTLS
	mbedtls_aes_crypt_ctr(&key->mbedtls_aes_ctx, payload_len, &key->aes_offset, key->iv, key->strean_block, inbuf, outbuf);
#elif HAVE_NETTLE
	nettle_cipher_func *f;
	switch(key->key_size) {
	case 128:
		f = (nettle_cipher_func *)nettle_aes128_encrypt;
		break;
	case 192:
		f = (nettle_cipher_func *)nettle_aes192_encrypt;
		break;
	case 256:
		f = (nettle_cipher_func *)nettle_aes256_encrypt;
		break;
	default:
		return;
	}
	nettle_ctr_crypt(&key->nettle_ctx.u, f, AES_BLOCK_SIZE, key->iv,payload_len, outbuf, inbuf);
#elif defined(LINUX_CRYPTO)
	if (key->linux_crypto_ctx)
		linux_crypto_decrypt(inbuf, outbuf, payload_len, key->iv, key->linux_crypto_ctx);
	else
		aes_decrypt_ctr(inbuf, payload_len, outbuf,	key->aes_key_sched, key->key_size, key->iv);
#else
	aes_decrypt_ctr(inbuf, payload_len, outbuf, key->aes_key_sched, key->key_size, key->iv);
#endif
    key->used_times++;
}

static void _librist_crypto_psk_prepare_iv(struct rist_key *key, uint8_t gre_version, uint32_t seq_nbe) {
    /* Prepare AES iv */
    // The byte array needs to be zeroes and then the seq in network byte order
    uint8_t copy_offset = gre_version >= 1 ? 0 : 12;
    memset(key->iv, 0, 16);
    memcpy(key->iv + copy_offset, &seq_nbe, sizeof(seq_nbe));
}

static void _librist_crypto_psk_generate_nonce(struct rist_key *key) {
	/* Fail-closed CSPRNG: on failure, mark the key locked so encrypt/decrypt
	 * short-circuit instead of running AES under a predictable nonce. */
	uint32_t nonce_val = 0;
	for (int attempts = 0; attempts < 8; attempts++) {
		if (_librist_crypto_random_u32(&nonce_val) != 0) {
			rist_log_priv3(RIST_LOG_ERROR,
				"PSK nonce generation: CSPRNG unavailable, "
				"PSK encrypt/decrypt locked out until passphrase rotation\n");
			key->csprng_failed = true;
			key->bad_decryption = true;
			return;
		}
		if (nonce_val != 0)
			break;
	}
	if (nonce_val == 0) {
		/* 8 zeros in a row from a working CSPRNG is 2^-256; treat as malfunction. */
		rist_log_priv3(RIST_LOG_ERROR,
			"PSK nonce generation: CSPRNG returned only zeros, locking out\n");
		key->csprng_failed = true;
		key->bad_decryption = true;
		return;
	}

	memcpy(key->gre_nonce, &nonce_val, sizeof(key->gre_nonce));

    UNSET_BIT(key->gre_nonce[0], 7);
    if (key->odd)
        SET_BIT(key->gre_nonce[0], 7);
}

void _librist_crypto_psk_decrypt(struct rist_key *key, uint8_t nonce[4], uint32_t seq_nbe, uint8_t gre_version, const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len)
{
	uint32_t nonce_val;
	memcpy(&nonce_val, nonce, sizeof(nonce_val));
    // A zero nonce never comes from a legitimate sender; refuse to decrypt
    if (!nonce_val) {
        key->bad_decryption = true;
        return;
    }

    if (memcmp(nonce, key->gre_nonce, sizeof(key->gre_nonce)) != 0) {
        /* Skip PBKDF2 + rekey while locked out. */
        if (key->bad_decryption)
            return;
        memcpy(key->gre_nonce, nonce, sizeof(key->gre_nonce));
        _librist_crypto_aes_key(key);
        /* Only clear the flag if _librist_crypto_aes_key succeeded;
         * it sets bad_decryption=true on PBKDF2/setup failure. */
        if (!key->bad_decryption)
            key->bad_count = 0;
    }

    if (key->used_times > RIST_AES_KEY_REUSE_TIMES) {
        key->bad_decryption = true;
        return;
    }

    _librist_crypto_psk_prepare_iv(key, gre_version, seq_nbe);
#if HAVE_MBEDTLS
    key->aes_offset = 0;
#endif
    _librist_crypto_psk_aes_ctr(key, inbuf, outbuf, payload_len);
    return;
}

void _librist_crypto_psk_encrypt(struct rist_key *key, uint32_t seq_nbe, uint8_t gre_version,const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len)
{
    uint32_t nonce_val;
    memcpy(&nonce_val, key->gre_nonce, sizeof(nonce_val));
    if (!nonce_val || (key->used_times +1) > RIST_AES_KEY_REUSE_TIMES || (key->key_rotation > 0 && key->used_times >= key->key_rotation)) {
        _librist_crypto_psk_generate_nonce(key);
        if (key->csprng_failed) {
            memset(outbuf, 0, payload_len);
            return;
        }
        _librist_crypto_aes_key(key);
    }
    if (key->csprng_failed) {
        memset(outbuf, 0, payload_len);
        return;
    }
    _librist_crypto_psk_prepare_iv(key, gre_version, seq_nbe);
#if HAVE_MBEDTLS
    key->aes_offset = 0;
#endif
    _librist_crypto_psk_aes_ctr(key, inbuf, outbuf, payload_len);
    return;
}

int _librist_crypto_psk_set_passphrase(struct rist_key *key, const uint8_t *passsphrase, size_t passphrase_len) {
	if (passphrase_len > sizeof(key->password) -1) {
		return -1;
	}
	if (key->key_size == 0)
		key->key_size = 256;
	memcpy(key->password, passsphrase, passphrase_len);
	key->password_len = passphrase_len;
	key->used_times = 0;
	key->csprng_failed = false; /* fresh passphrase, retry CSPRNG */
	_librist_crypto_psk_generate_nonce(key);
	_librist_crypto_aes_key(key);
	return 0;
}

void _librist_crypto_psk_get_passphrase(struct rist_key *key, const uint8_t **passphrase, size_t *passphrase_len) {
	*passphrase = key->password;
	*passphrase_len = key->password_len;
}

void _librist_crypto_psk_encrypt_continue(struct rist_key *key, const uint8_t inbuf[], uint8_t outbuf[], size_t payload_len) {
	_librist_crypto_psk_aes_ctr(key, inbuf, outbuf, payload_len);
}

void _librist_crypto_psk_preannounce_nonce(struct rist_key *key, const uint8_t nonce[4], uint32_t key_size_bits) {
	uint32_t nonce_val;
	memcpy(&nonce_val, nonce, sizeof(nonce_val));
	if (!nonce_val)
		return;
	if (memcmp(nonce, key->gre_nonce, sizeof(key->gre_nonce)) == 0)
		return;
	if (key_size_bits)
		key->key_size = key_size_bits;
	memcpy(key->gre_nonce, nonce, sizeof(key->gre_nonce));
	_librist_crypto_aes_key(key);
}
