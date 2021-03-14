# SCEWL Controller Universal Messaging (SCUM)

```
░██████╗░█████╗░██╗░░░██╗███╗░░░███╗
██╔════╝██╔══██╗██║░░░██║████╗░████║
╚█████╗░██║░░╚═╝██║░░░██║██╔████╔██║
░╚═══██╗██║░░██╗██║░░░██║██║╚██╔╝██║
██████╔╝╚█████╔╝╚██████╔╝██║░╚═╝░██║
╚═════╝░░╚════╝░░╚═════╝░╚═╝░░░░░╚═╝
```

## Algorithmic Overview

SCUM is based on the Secure Real-time Transport Protocol (SRTP) (this means it works perfectly, clearly), using an authenticated symmetric cipher suite for data streaming.
SCUM uses the AES-256 GCM variant of SRTP defined in [RFC 7714](https://tools.ietf.org/html/rfc7714), with a 256-bit symmetric key and 16-byte authentication tag. SCUM
differs from SRTP in the following key aspects:

1. SCUM uses the authenticated SRTP global sequence number as a means for preventing replay attacks
    - SEDs only accept the current message count, or a message count from the future to simplify unsynchronized state recovery
    - SRTP uses a database of previous messages to detect replays within a recent message window
    - SRTP does not use the sequence number in a cryptographic way at the protocol layer, but suggests it may be used for
      security features at the application layer
2. SCUM does NOT have an accompanying Secure Real-time Transport Control Protocol (SRTCP)
    - SRTP is accompanied by a control channel that indicates beginnings and ends of streams, in addition to other functionality

At registration, each SED is given a deployment-specific cryptographic state including a *master key* and *master salt*. These two values are used to to derive all the other keys used in broadcast messaging.
SCUM re-keys the data stream at a fixed Key Derivation Rate (KDR). A *data key* and *data salt* are derived from the master secrets which are used as a component of the GCM IV and GCM key, respectively.
The data secrets are updated every time the sequence number reaches a multiple of the KDR. The key derivation function is compliant with the specification in
[RFC 3711 Section 4.3](https://tools.ietf.org/html/rfc3711#section-4.3).

In order to meet memory requirements, each maximum sized SCEWL application message is broken into smaller SCUM frames which are repeatedly sent by the broadcaster, with each frame inducing a global sequence
count increment. The last frame in an application-level message is indicated with an authenticated SCUM header `end_marker` field.

The SCUM header format is as follows:

| Field           | Bits |
|-----------------|------|
| end_marker      | 8    |
| type            | 8    |
| length          | 16   |
| sequence_number | 64   |

The `type` field can take on one of the following values: `SYNC_REQ`, `SYNC_RESP`, `DATA`. All frames in the data channel have a type of `DATA`, while
frames on the *sync channel*, discussed next, use the other two values.


## Synchronization

One clear challenge with SCUM broadcasting is that all devices must consistently share the global sequence number, which may be violated when a new SED registers onto the network. The first
SED registered is given a 'Pre-Synced' status by the SSS, which indicates that the SED does not need to perform a synchronization routine. Any other SED that registers is configured into
an 'UNSYNC' state, and repeatedly sends a synchronization request every 10 seconds until it receives a response.

Synchronization happens on a separate channel from the data stream, called the *sync channel*. The sync channel is NOT subject to the same global sequence number requirement as the data channel. Instead, replay protection
is provided through a challenge/response transaction. Furthermore, the sync channel and data channel have entirely separate, randomly generated mater cryptographic states that are provided by the SSS during registration.
The synchronization transaction occurs as follows:

1. Unsynced SED generates a string of random bytes, sends encrypted over the sync channel
2. Synchronized SEDs that are NOT RECEIVING decrypt the sync request, and add a masked copy of the current sequence number. This forms the sync response:
    - Request challenge bytes
    - Random mask
    - Random mask XOR sequence number
3. Unsynced SED receives all sync responses, and evaluates them until it gets the first valid response
    - The SED decrypts the response and verifies that the original challenge message is in the response
    - The SED removes the mask from the sequence number, updates the data channel count, and refreshes the data keys appropriately

**Sync Request**
```
|------------|----------|-----------|-------|-----------|
| end marker |   type   | length(B) | seq # |   data    |
|------------|----------|-----------|-------|-----------|
|     0      | SYNC_REQ |     8     |   0   | rand0 (8) |
|------------|----------|-----------|-------|-----------|
```

**Sync Response**
```
|------------|-----------|-----------|-------|----------------------------------------|
| end marker |   type    | length(B) | seq # |                 data                   |
|------------|-----------|-----------|-------|----------------------------------------|
|     0      | SYNC_RESP |    24     |   0   | rand0 (8), rand1 (8), rand1 ^ seq# (8) |
|------------|-----------|-----------|-------|----------------------------------------|
```

In the event that an SED misses a message and receives a SCUM frame with a sequence number from the future that is beyond the next KDR multiple, the SED will fail to authenticate and decrypt the frame.
In this case, the SED will test if updated keys will work for decryption. This is done by temporarily forwarding its sequence number to the sequence number of the received frame, refreshing the data keys,
and re-attempting decryption/authentication.

If this test is successful, the SED will keep the new sequence number and keys, and continue as normal. If the test fails, it reverts to its old key state. This is to allow maximum flexibility with strange
network race conditions while staying resilient to corrupted attacker messages.


## Authentication

The entire header of every SCUM frame is authenticated by the GCM tag. As opposed to the HMAC technique proposed by the first variant of SRTP, the GCM
tag encrypts the data plaintext, and adds the plaintext as well as additional data (the header) into a cryptographic authentication tag, with
encryption and authentication tag calculation happening concurrently, as opposed to sequentially in HMAC. This means that the header can only be
authenticated once decryption has been completed. In order to work around this limitation, **the only decisions made on the header before authentication
is to set up data lengths**. The SCUM implementation will only accept SCUM header length fields that fit within the SCEWL MTU, taking into account
the header and tag overhead. All data is processed into a staging buffer that is allocated to support the maximum data size.


## Meeting Functional Requirements

SCUM meets the traditional confidentiality, integrity, and authentication properties through the use of a cryptographically strong symmetric key
algorithm that uses cryptographically secure pseud-random functions to update keys and salts. Since all registered SEDs share the same data and sync
keys, the authentication tag provides both integrity and authenticity, since a valid tag can only be computed if the key is known.

The protocol protects against replay attacks by enforcing a monotonic global sequence number on every data frame.

The data size of the sequence number ensures that all of the cryptographic and functional limits of the system are achievable. SRTP
only allows keys to be used for up to 2^48 messages, and since each application level message may be broken down into < 17 SCUM frames, the total
number of frames sent in a non-attack scenario is ~ 2^32 * 17, which is well under the SRTP limit.

Furthermore, the RNG instance used for generating sync request messages is subject to the 2^48 generation limit enforced by HMAC DRBG, which is well
under the amount of sync request/response messages that must be supported.