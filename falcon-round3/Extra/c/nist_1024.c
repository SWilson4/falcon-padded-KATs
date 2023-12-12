/*
 * Wrapper for implementing the NIST API for the PQC standardization
 * process.
 */

#include <stddef.h>
#include <string.h>

#include "api.h"
#include "falcon.h"
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
		uint8_t b[FALCON_KEYGEN_TEMP_10];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC int8_t f[1024], g[1024], F[1024];
	TEMPALLOC uint16_t h[1024];
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
	Zf(keygen)(&rng, f, g, F, NULL, h, 10, tmp.b);


	/*
	 * Encode private key.
	 */
	sk[0] = 0x50 + 10;
	u = 1;
	v = Zf(trim_i8_encode)(sk + u, CRYPTO_SECRETKEYBYTES - u,
		f, 10, Zf(max_fg_bits)[10]);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_encode)(sk + u, CRYPTO_SECRETKEYBYTES - u,
		g, 10, Zf(max_fg_bits)[10]);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_encode)(sk + u, CRYPTO_SECRETKEYBYTES - u,
		F, 10, Zf(max_FG_bits)[10]);
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
	pk[0] = 0x00 + 10;
	v = Zf(modq_encode)(pk + 1, CRYPTO_PUBLICKEYBYTES - 1, h, 10);
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
		uint8_t b[FALCON_TMPSIZE_SIGNDYN(10)];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC int8_t f[1024], g[1024], F[1024], G[1024];
	TEMPALLOC union {
		int16_t sig[1024];
		uint16_t hm[1024];
	} r;
	TEMPALLOC unsigned char seed[48], nonce[NONCELEN];
	TEMPALLOC inner_shake256_context sc_rng;
	TEMPALLOC inner_shake256_context sc_hashdata;
	size_t u, v, sig_len;
    int ret;

	/*
	 * Decode the private key.
	 */
	if (sk[0] != 0x50 + 10) {
		return -1;
	}
	u = 1;
	v = Zf(trim_i8_decode)(f, 10, Zf(max_fg_bits)[10],
		sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_decode)(g, 10, Zf(max_fg_bits)[10],
		sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_decode)(F, 10, Zf(max_FG_bits)[10],
		sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	if (u != CRYPTO_SECRETKEYBYTES) {
		return -1;
	}
	if (!Zf(complete_private)(G, f, g, F, 10, tmp.b)) {
		return -1;
	}

	/*
	 * Create a random nonce (40 bytes).
	 */
	randombytes(nonce, sizeof nonce);

	/*
	 * Hash message nonce + message into a vector.
	 */
	inner_shake256_init(&sc_hashdata);
	inner_shake256_inject(&sc_hashdata, nonce, sizeof nonce);
	inner_shake256_inject(&sc_hashdata, m, mlen);
	//inner_shake256_flip(&sc_hashdata);
	//Zf(hash_to_point_vartime)(&sc_hashdata, r.hm, 10);
    // need to save this hash data

	/*
	 * Initialize a RNG.
	 */
	randombytes(seed, sizeof seed);
	inner_shake256_init(&sc_rng);
	inner_shake256_inject(&sc_rng, seed, sizeof seed);
	inner_shake256_flip(&sc_rng);


	/*
	 * Compute the signature.
	 */
    sig_len = CRYPTO_BYTES;
    if ((ret = falcon_sign_dyn_finish((shake256_context *)&sc_rng, sm, &sig_len, FALCON_SIG_PADDED, sk, CRYPTO_SECRETKEYBYTES, (shake256_context *)&sc_hashdata, nonce, tmp.b, sizeof(tmp.b))) != 0) {
        return ret;
    }
	//Zf(sign_dyn)(r.sig, &sc_rng, f, g, F, G, r.hm, 10, tmp.b);



	/*
	 * Encode the signature and bundle it with the message. Format is:
	 *   signature length     2 bytes, big-endian
	 *   nonce                40 bytes
	 *   message              mlen bytes
	 *   signature            slen bytes
	 */
	//esig[0] = 0x20 + 10;
	//sig_len = Zf(comp_encode)(esig + 1, (sizeof esig) - 1, r.sig, 10);
	if (sig_len == 0) {
		return -1;
	}
	//sig_len ++;
	memmove(sm + sig_len, m, mlen);
	*smlen = sig_len + mlen;
	//sm[0] = (unsigned char)(sig_len >> 8);
	//sm[1] = (unsigned char)sig_len;
	//memcpy(sm + 2, nonce, sizeof nonce);
	//memcpy(sm + 2 + (sizeof nonce) + mlen, esig, sig_len);
	//*smlen = 2 + (sizeof nonce) + mlen + sig_len;
	return 0;
}

int
crypto_sign_open(unsigned char *m, unsigned long long *mlen,
	const unsigned char *sm, unsigned long long smlen,
	const unsigned char *pk)
{
	TEMPALLOC union {
		uint8_t b[2 * 1024];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC uint16_t h[1024], hm[1024];
	TEMPALLOC int16_t sig[1024];
	TEMPALLOC inner_shake256_context sc;
	size_t sig_len, msg_len;

	/*
	 * Decode public key.
	 */
	if (pk[0] != 0x00 + 10) {
		return -1;
	}
	if (Zf(modq_decode)(h, 10, pk + 1, CRYPTO_PUBLICKEYBYTES - 1)
		!= CRYPTO_PUBLICKEYBYTES - 1)
	{
		return -1;
	}
	Zf(to_ntt_monty)(h, 10);

	/*
	 * Find nonce, signature, message length.
	 */
	if (smlen < CRYPTO_BYTES) {
		return -3;
	}
    /*
	sig_len = ((size_t)sm[0] << 8) | (size_t)sm[1];
	if (sig_len > (smlen - 2 - NONCELEN)) {
		return -1;
	}
    */
	msg_len = smlen - CRYPTO_BYTES;

	/*
	 * Decode signature.
	 */
	if (sm[0] != 0x30 + 10) {
		return -5;
	}
    /*
	if (Zf(comp_decode)(sig, 10,
		esig + 1, sig_len - 1) != sig_len - 1)
	{
		return -1;
	}
    */

	/*
	 * Hash nonce + message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, sm + 1, NONCELEN);
	inner_shake256_inject(&sc, sm + CRYPTO_BYTES, msg_len);
	//inner_shake256_flip(&sc);
	//Zf(hash_to_point_vartime)(&sc, hm, 10);

    if (!falcon_verify_finish(sm, CRYPTO_BYTES, FALCON_SIG_PADDED, pk, CRYPTO_PUBLICKEYBYTES, (shake256_context *)&sc, tmp.b, sizeof(tmp.b))) {

	/*
	 * Verify signature.
	 */
	//if (!Zf(verify_raw)(hm, sig, h, 10, tmp.b)) {
		return -1;
	}

	/*
	 * Return plaintext.
	 */
	memmove(m, sm + CRYPTO_BYTES, msg_len);
	*mlen = msg_len;
	return 0;
}
