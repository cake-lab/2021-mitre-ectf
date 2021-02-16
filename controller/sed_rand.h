/*
 * Author: Jake Grycel - jtgrycel@wpi.edu
 * Description: Random number generator reseeding manager
 */


#ifndef SED_RAND_H
#define SED_RAND_H

/*
 * Included Libs
 */

#include <stddef.h>

/*
 * Function Prototypes
 */

int sed_seed_request(void *in_data, unsigned char *output, size_t req_len);


#endif // SED_RAND_H