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
#include <stddef.h>

/*
 * Function Prototypes
 */

int rng_module_setup(mbedtls_hmac_drbg_context *hmac_drbg, unsigned char *pers_str, size_t pers_len);
int sed_seed_request(void *in_data, unsigned char *output, size_t req_len);


#endif // SED_RAND_H