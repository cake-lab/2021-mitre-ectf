# Random Number Generation

All system components that require random numbers use the HMAC DRBG
implementation from MbedTLS. HMAC DRBG is an HMAC-based Deterministic Random Bit
Generator defined in [NIST SP 800-90A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf)
with strict limits and recommendations on seed management and generation limits.
The MbedTLS implementation of HMAC DRBG uses a Nonce in the seeding of the RNG
in addition to values gathered from an entropy pool for a total of 48 bytes of
entropy, safely above the minimum requirement of 32 bytes defined by NIST.

Each reseeding of the RNG allows cryptographically safe generation of 2^48
random values, which is well under the maximum number of random values needed
by the system.

For example, an SED performing DoS communication will generate 2 or 3 values for
the handshake, plus an additional 2 or 3 for key generation. In the secure data
channel, one random value may be used for each MTU-sized packet. In total, this
is potentially 3+3+17 random values for each 16KB message. To meet the
requirement of supporting 2^32 messages, this comes to a conservative estimate
of ~99E9 values, which is well under the HMAC DRBG limit of 281.5E12 (2^48).


Since there are 3 instances of the RNG (DTLS, SCUM, Masked AES), each SED is
given 192 bytes of "entropy" to support 48 byte entropy seeds for each instance.
One entropy pool is provided at provision time, where the entropy pool is
compiled into the SED controller binary. A second entropy pool is given to the
SED by the SSS during a successful registration. This run-time entropy pool
replaces the provision-time one in all 3 RNG instances until deregistration.
Upon de-registration, the SED returns to using the provision-time pool.

If an HMAC DRBG instance is asked for more than 2^48 values, it will attempt to
reseed with the current entropy pool. However, the entropy pool keeps track of
how many seed requests have been made. If more requests are made than is
available in the pool (and more than is necessary for the message limit), the
SED will cease to operate since it is outside of its required operating state.