/*
 * Author: Jake Grycel - jtgrycel@wpi.edu
 * Description: Random number generator reseeding manager
 */

#include "controller.h"
#include "sed_rand.h"
#include "sed_secrets.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/hmac_drbg.h"

// Definitions
#define SEED_WIDTH 32

/*
 * Configure an HMAC_DRBG instance for appropriate NIST-compliant random generation
 */
int rng_module_setup(mbedtls_hmac_drbg_context *hmac_drbg, unsigned char *pers_str, size_t pers_len)
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
 * Seed function that checks for appropriate use by HMAC_DRBG
 * Expects to seed two HMAC_DRBG instances - one for DTLS, one for masked AES
 */
int sed_seed_request(void *in_data, unsigned char *output, size_t req_len)
{
  int i;
  static int req_count = 0;
  static int rd_addr = 0;

  // First request should be full length, second request should be half length
  switch (req_count){
    case 0:
      if (req_len != SEED_WIDTH)
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
      break;
    case 1:
      if (req_len != SEED_WIDTH/2)
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
      break;
    case 2:
      if (req_len != SEED_WIDTH)
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
      break;
    case 3:
      if (req_len != SEED_WIDTH/2)
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
      break;
    default:
      return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
  }

  // Copy the bytes
  for (i = 0; i < req_len; i++){
    *(output+i) = seed_pool[rd_addr++];
  }

  req_count++;

  return 0;
}