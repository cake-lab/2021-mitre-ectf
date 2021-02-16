/*
 * Author: Jake Grycel - jtgrycel@wpi.edu
 * Description: Random number generator reseeding manager
 */

#include "sed_rand.h"
#include "sed_secrets.h"
#include "mbedtls/entropy.h"

// Definitions
#define SEED_WIDTH 32

// Globals
int req_count = 0;

/*
 * Temporary working implementation always uses the same seed loaded from build process
 */
int sed_seed_request(void *in_data, unsigned char *output, size_t req_len)
{
  int i;
  int rd_addr;

  // First request should be full length, second request should be half length
  if (req_count == 0) {
    if (req_len != SEED_WIDTH) {
      return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    } else {
      rd_addr = 0;
    }
  } else if (req_count == 1){
    if (req_len != (SEED_WIDTH/2)){
      return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    } else {
      rd_addr = SEED_WIDTH;
    }
  } else if (req_count > 1) {
    return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
  }

  // Copy the bytes
  for (i = 0; i < req_len; i++){
    *(output+i) = seed_pool[rd_addr+i];
  }

  req_count++;

  return 0;
}