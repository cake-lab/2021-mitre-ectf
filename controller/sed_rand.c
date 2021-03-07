/*
 * Author: Jake Grycel - jtgrycel@wpi.edu
 * Description: Random number generator reseeding manager
 */

#include "controller.h"
#include "sed_rand.h"
#include "sed_secrets.h"
#include "mbedtls/platform.h"

/*
 * Globals
 */
static unsigned char runtime_seed_pool[ENTROPY_POOL_SIZE];
static unsigned char *pool_ptr = (unsigned char *)initial_seed_pool;
static int req_count = 0;
static int rd_addr = 0;


/*
 * Copy runtime seed pool
 */
void rng_load_runtime_pool(unsigned char *pool, int len) {
  if (len != ENTROPY_POOL_SIZE) {
    mbedtls_printf("Incorrect pool size provided");
    return;
  }
  memcpy(runtime_seed_pool, pool, len);
}

/*
 * Configure an HMAC_DRBG instance for appropriate NIST-compliant random generation
 */
int rng_setup(mbedtls_hmac_drbg_context *hmac_drbg, unsigned char *pers_str, size_t pers_len)
{
  int ret;

  /*
   * Setup random number generator and entropy source
   *
   * NIST SP 800-90B says upto 2^48 random numbers can be generated before a reseed
   *
   * Set up 32-byte entropy length for 256-bit security level in HMAC DRBG (SHA-256)
   *
   * The seed function simply returns the device seed acquired during registration
   *
   * During seeding neither the personalization string or nonce is required,
   * especially since our seed has full entropy
   */
  mbedtls_printf("Configuring random number generator ...");

  mbedtls_hmac_drbg_set_reseed_interval(hmac_drbg, (1ULL << 48));

  ret = mbedtls_hmac_drbg_seed(hmac_drbg, mbedtls_md_info_from_string("SHA256"), sed_seed_request, NULL, pers_str, pers_len);
  if(ret != 0) {
    mbedtls_printf("failed! mbedtls_hmac_drbg_seed returned -%#06x", (unsigned int) -ret);
  }
  return ret;
}

/*
 * Switch to runtime source
 */
int rng_setup_runtime_pool(mbedtls_hmac_drbg_context *hmac_drbg, unsigned char *pers_str, size_t pers_len)
{
  pool_ptr = runtime_seed_pool;
  req_count = 0;
  rd_addr = 0;
  return rng_setup(hmac_drbg, pers_str, pers_len);
}

/*
 * Switch to built-in provision source
 */
int rng_setup_initial_pool(mbedtls_hmac_drbg_context *hmac_drbg, unsigned char *pers_str, size_t pers_len)
{
  pool_ptr = (unsigned char *)initial_seed_pool;
  req_count = 0;
  rd_addr = 0;
  return rng_setup(hmac_drbg, pers_str, pers_len);
}

/*
 * Seed function that checks for appropriate use by HMAC_DRBG
 * Expects to seed two HMAC_DRBG instances - one for DTLS, one for masked AES
 */
int sed_seed_request(void *in_data, unsigned char *output, size_t req_len)
{
  int i;

  // Only perfom as many reseeds are there are seeds available
  if (req_count >= MAX_CALLS) {
    mbedtls_printf("Entropy has run out for an HMAC_DRBG instance");
    exit(1);
  }

  // First request should be full length, second request should be half length
  if (((req_count % 2) == 0) && (req_len != SEED_WIDTH)) {
    mbedtls_printf("Unexpected entropy seed request length. Dying");
    exit(1);
  } else if (((req_count % 2) == 1) && (req_len != SEED_WIDTH/2)) {
    mbedtls_printf("Unexpected entropy seed request length. Dying");
    exit(1);
  }

  // Copy the bytes
  for (i = 0; i < req_len; i++){
    *(output+i) = pool_ptr[rd_addr++];
  }

  req_count++;

  return 0;
}