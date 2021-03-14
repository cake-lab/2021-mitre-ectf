# Side-Channel Analysis Countermeasures

The SCEWL controller utilizes a number of countermeasures to make side-channel
attacks harder. The countermeasures are placed on the two main cryptographic
primitives used in Dos and SCUM: RSA and AES. The MbedTLS implementation of RSA
uses the exponent blinding technique to prevent timing attacks, which can also
translate to power side-channel attacks.

To discourage side-channel attacks on AES, the controller uses a [Byte-masked
AES 256 implementation](https://github.com/CENSUS/masked-aes-c) that utilizes 10
random masks. The copy of this implementation included in this repository has
been modified to remove unused parts of the code (128/192 bit key functionality,
block cipher mode functions) to only use the 256-bit masked
encryption/decryption core.

The [modified MbedTLS AES module](../controller/mbedtls_custom/library/aes.c)
then calls the masked ECB core when performing different block cipher modes.
This implementation was selected due to its support for masking 256-bit keys
without using a specific mode of operation. The modifications to the masked
ECB core also implement using an HMAC DRBG instance as the mask generation
primitive. The HMAC DRBG instance used for AES masks resides in the main
controller loop to avoid extra unnecessary changes to the original masked AES
repo.