#include <px4_random.h>
#include <tomcrypt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

__attribute__((weak)) void *calloc(size_t nmemb, size_t size)
{
	static uint8_t pool[64 * 1024];
	static size_t offset = 0;

	if (nmemb == 0 || size == 0) {
		return NULL;
	}

	if (nmemb > (SIZE_MAX / size)) {
		return NULL;
	}

	size_t total = nmemb * size;
	total = (total + 7U) & ~(size_t)7U;

	if (offset > sizeof(pool) || total > (sizeof(pool) - offset)) {
		return NULL;
	}

	void *ptr = &pool[offset];
	offset += total;
	memset(ptr, 0, total);

	return ptr;
}

__attribute__((weak)) size_t px4_get_secure_random(uint8_t *out,
		size_t outlen)
{
	static uint32_t state = 0x1A2B3C4DU;

	if (!out) {
		return 0;
	}

	for (size_t i = 0; i < outlen; i++) {
		state ^= (state << 13);
		state ^= (state >> 17);
		state ^= (state << 5);
		out[i] = (uint8_t)(state & 0xFFU);
	}

	return outlen;
}

struct ltc_hash_descriptor hash_descriptor[] = {
	{
		"sha256",
		0,
		32,
		64,

		/* OID */
		{ 2, 16, 840, 1, 101, 3, 4, 2, 1,  },
		9,

		&sha256_init,
		&sha256_process,
		&sha256_done,
		&sha256_test,
		NULL
	}
};

struct ltc_prng_descriptor prng_descriptor[] = {
	{
		"sprng", 0,
		&sprng_start,
		&sprng_add_entropy,
		&sprng_ready,
		&sprng_read,
		&sprng_done,
		&sprng_export,
		&sprng_import,
		&sprng_test
	}
};

unsigned long rng_get_bytes(unsigned char *out,
			    unsigned long outlen,
			    void (*callback)(void))
{
	return px4_get_secure_random((uint8_t *)out, (size_t)outlen);
}

void libtomcrypt_init(void)
{
	ltc_mp = ltm_desc;
}
