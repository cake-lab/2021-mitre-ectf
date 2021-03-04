# Changelog for masked-aes-c

Original code downloaded from https://github.com/CENSUS/masked-aes-c

- aes.c, aes.h renamed to masked_aes.c, masked_aes.h, respectively
- CipherMasked(...) and InvCipherMasked(...) prototypes added to masked_aes.h
  to allow for external access to the core functions. Static keyword was removed
  to satisfy compiler
- state_t typedef moved to masked_aes.h for external access/definition
- Adds reference to `mbedtls` `hmac_drbg` for generating random masks
    - Uses global reference which is set by the application setup
    - Adds `Masked_AES_RNG_Setup` function to set the reference and initialize
      HMAC_DRBG
        - Will return failure if seeding fails
- Modifies `Masked` functions to return failure if getting a random number fails
- Comments out un-masked functions that are not used
    - `Cipher`, `InvCipher`, `AddRoundKey`, `SubBytes`, `InvSubBytes`