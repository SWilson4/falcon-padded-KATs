/*
 * Wrapper for implementing the NIST API for the PQC standardization
 * process.
 */

#include <stddef.h>
#include <string.h>

#include "api.h"
#include "inner.h"

#define NONCELEN   40

/*
 * If stack usage is an issue, define TEMPALLOC to static in order to
 * allocate temporaries in the data section instead of the stack. This
 * would make the crypto_sign_keypair(), crypto_sign(), and
 * crypto_sign_open() functions not reentrant and not thread-safe, so
 * this should be done only for testing purposes.
 */
#define TEMPALLOC

void randombytes_init(unsigned char *entropy_input,
	unsigned char *personalization_string,
	int security_strength);
int randombytes(unsigned char *x, unsigned long long xlen);

int
crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
	TEMPALLOC union {
		uint8_t b[FALCON_KEYGEN_TEMP_9];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC int8_t f[512], g[512], F[512];
	TEMPALLOC uint16_t h[512];
	TEMPALLOC unsigned char seed[48];
	TEMPALLOC inner_shake256_context rng;
	size_t u, v;


	/*
	 * Generate key pair.
	 */
	randombytes(seed, sizeof seed);
	inner_shake256_init(&rng);
	inner_shake256_inject(&rng, seed, sizeof seed);
	inner_shake256_flip(&rng);
	Zf(keygen)(&rng, f, g, F, NULL, h, 9, tmp.b);


	/*
	 * Encode private key.
	 */
	sk[0] = 0x50 + 9;
	u = 1;
	v = Zf(trim_i8_encode)(sk + u, CRYPTO_SECRETKEYBYTES - u,
		f, 9, Zf(max_fg_bits)[9]);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_encode)(sk + u, CRYPTO_SECRETKEYBYTES - u,
		g, 9, Zf(max_fg_bits)[9]);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_encode)(sk + u, CRYPTO_SECRETKEYBYTES - u,
		F, 9, Zf(max_FG_bits)[9]);
	if (v == 0) {
		return -1;
	}
	u += v;
	if (u != CRYPTO_SECRETKEYBYTES) {
		return -1;
	}

	/*
	 * Encode public key.
	 */
	pk[0] = 0x00 + 9;
	v = Zf(modq_encode)(pk + 1, CRYPTO_PUBLICKEYBYTES - 1, h, 9);
	if (v != CRYPTO_PUBLICKEYBYTES - 1) {
		return -1;
	}

	return 0;
}

int
crypto_sign(unsigned char *sm, unsigned long long *smlen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk)
{
	TEMPALLOC union {
		uint8_t b[72 * 512];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC int8_t f[512], g[512], F[512], G[512];
	TEMPALLOC union {
		int16_t sig[512];
		uint16_t hm[512];
	} r;
	TEMPALLOC unsigned char seed[48], nonce[NONCELEN];
	TEMPALLOC inner_shake256_context sc;
	size_t u, v, sig_len;

	/*
	 * Decode the private key.
	 */
	if (sk[0] != 0x50 + 9) {
		return -1;
	}
	u = 1;
	v = Zf(trim_i8_decode)(f, 9, Zf(max_fg_bits)[9],
		sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		return -2;
	}
	u += v;
	v = Zf(trim_i8_decode)(g, 9, Zf(max_fg_bits)[9],
		sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		return -3;
	}
	u += v;
	v = Zf(trim_i8_decode)(F, 9, Zf(max_FG_bits)[9],
		sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		return -4;
	}
	u += v;
	if (u != CRYPTO_SECRETKEYBYTES) {
		return -5;
	}
	if (!Zf(complete_private)(G, f, g, F, 9, tmp.b)) {
		return -6;
	}

	/*
	 * Create a random nonce (40 bytes).
	 */
	randombytes(nonce, sizeof nonce);

	/*
	 * Hash message nonce + message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, nonce, sizeof nonce);
	inner_shake256_inject(&sc, m, mlen);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, r.hm, 9);
    // need to save this hash data

	/*
	 * Initialize a RNG.
	 */
	randombytes(seed, sizeof seed);
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, seed, sizeof seed);
	inner_shake256_flip(&sc);


	/*
	 * Compute the signature.
	 */
    // falcon_sign_dyn_finish(&sc, sig, CRYPTO_BYTES, FALCON_SIG_COMPRESSED,
    // sk, CRYPTO_SECRETKEYBYTES, nonce, tmp.b, sizeof(tmp.b))
	Zf(sign_dyn)(r.sig, &sc, f, g, F, G, r.hm, 9, tmp.b);



	/*
	 * Encode the signature and bundle it with the message. Format is:
	 *   signature length     2 bytes, big-endian
	 *   nonce                40 bytes
	 *   message              mlen bytes
	 *   signature            slen bytes
	 */
	sm[0] = 0x30 + 9;
	sig_len = Zf(comp_encode)(sm + 1 + sizeof nonce, CRYPTO_BYTES - sizeof nonce - 3, r.sig, 9);
	if (sig_len == 0) {
		return -7;
	}
	sig_len ++;
	memmove(sm + sizeof nonce + sig_len, m, mlen);
	sm[sizeof nonce + mlen + sig_len] = (unsigned char)(sig_len >> 8);
	sm[sizeof nonce + mlen + sig_len + 1] = (unsigned char)sig_len;
	memcpy(sm + 1, nonce, sizeof nonce);
	*smlen = 2 + (sizeof nonce) + mlen + sig_len;
	return 0;
}

int
crypto_sign_open(unsigned char *m, unsigned long long *mlen,
	const unsigned char *sm, unsigned long long smlen,
	const unsigned char *pk)
{
	TEMPALLOC union {
		uint8_t b[2 * 512];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC uint16_t h[512], hm[512];
	TEMPALLOC int16_t sig[512];
	TEMPALLOC inner_shake256_context sc;
	size_t sig_len, msg_len;

	/*
	 * Decode public key.
	 */
	if (pk[0] != 0x00 + 9) {
		return -1;
	}
	if (Zf(modq_decode)(h, 9, pk + 1, CRYPTO_PUBLICKEYBYTES - 1)
		!= CRYPTO_PUBLICKEYBYTES - 1)
	{
		return -2;
	}
	Zf(to_ntt_monty)(h, 9);

	/*
	 * Find nonce, signature, message length.
	 */
	if (smlen < 2 + NONCELEN) {
		return -3;
	}
	sig_len = ((size_t)sm[smlen-2] << 8) | (size_t)sm[smlen-1];
	if (sig_len > (smlen - 2 - NONCELEN)) {
		return -4;
	}
	msg_len = smlen - 2 - NONCELEN - sig_len;

	/*
	 * Decode signature.
	 */
	if (sig_len < 1 || sm[0] != 0x30 + 9) {
		return -5;
	}
	if (Zf(comp_decode)(sig, 9,
		sm + 1 + NONCELEN, sig_len - 1) != sig_len - 1)
	{
		return -6;
	}

	/*
	 * Hash nonce + message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, sm + 1, NONCELEN);
	inner_shake256_inject(&sc, sm + NONCELEN + sig_len, msg_len);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, hm, 9);

	/*
	 * Verify signature.
	 */
	if (!Zf(verify_raw)(hm, sig, h, 9, tmp.b)) {
		return -7;
	}

	/*
	 * Return plaintext.
	 */
	memmove(m, sm + NONCELEN + sig_len, msg_len);
	*mlen = msg_len;
	return 0;
}
