/*
 * Author: Jake Grycel - jtgrycel@wpi.edu
 * Description: Random number generator reseeding manager
 */


#ifndef SED_RAND_H
#define SED_RAND_H

/*
 * Included Libs
 */

#include "mbedtls/hmac_drbg.h"
#include "scewl.h"

/*
 * Definitions
 */

#define ENTROPY_POOL_SIZE 192
#define SEED_WIDTH 32
#define MAX_CALLS (ENTROPY_POOL_SIZE/48)*2

/*
 * Function Prototypes
 */

int rng_setup(mbedtls_hmac_drbg_context *hmac_drbg, unsigned char *pers_str, size_t pers_len);
void rng_setup_runtime_pool(unsigned char *pool, int len);
void rng_clear_runtime_pool(void);
int sed_seed_request(void *in_data, unsigned char *output, size_t req_len);

#endif // SED_RAND_H