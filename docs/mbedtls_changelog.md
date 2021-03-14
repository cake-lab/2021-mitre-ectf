# Changelog for mbedtls_custom

## hmac_drbg

- Switches to using `long long` datatype for `reseed_interval` and `reseed_counter`
    - This is to support up to the maximum approved generation count of 2^48 in
      NIST SP 800-90A

## aes

- `aes.c`
    - `mbedtls_aes_setkey_dec` modified to prevent calculation of the inverse
      key schedule when using non-accelerated AES
        - Extra aes_ctx is only created if HW acceleration is enabled on Intel
    - Utilizes *masked-aes-c* functions `CipherMasked` and `InvCipherMasked`
      respectively for ECB encryption
        - This is the fundamental AES operation in `mbedtls`, and will be used
          by any mode of operation
    - Passes number of rounds to *masked-aes-c* functions to support different
      key lengths
    - Comment out definitions of reverse and forward table 0's
        - Even with `MBEDTLS_AES_ROM_TABLES` and `MBEDTLS_AES_FEWER_TABLES`
          defined, there are warnings due to the mbedtls AES core not being used