# SCEWL Bus Controller
The SCEWL Bus Controller implements the security and functionality of the SCEWL
protocol and is one of two components your team must implement (the other being
the SSS in `/sss/`). The SCEWL Bus Controller runs on a Stellaris lm3s6965 chip,
which will be emulated using qemu-system-arm.

The SCEWL Bus Controller is split into the following files:

* `controller.{c,h}`: Implements the main functionality of the SCEWL Bus
  Controller. It contains `main()` and handles the message passing of the system
* `interface.{c,h}`: Implements the interface to the hardware interfaces, reading
  and writing raw bytes. **NOTE: it is your responsibility to format bytes written
  to the interfaces as specified in Section 4.6 of the rules.** Malformed messages
  may be mangled or dropped completely by the network backend emulation. There is
  a good chance that you will not need to change `interface.{c,h}` in your design.
* `dtls.{c,h}`: Implements DTLS over SCEWL (DoS) unicast messaging between two
  SEDs, and an SED and the SSS. See the [DoS documentation](../docs/dtls.md) for
  more discussion.
* `broadcast.{c,h}`: Implements SCEWL Controller Universal Messaging (SCUM), the
  broadcast protocol used between all SEDs. See the
  [SCUM documentation](../docs/scum.md) for more discussion.
* `flash_buffers.{c,h}`: Implements the Flash buffer reading/writing
  functionality discussed in the [buffer documentation](../docs/buffers.md)
* `sed_rand.{c,h}`: Implements the SCEWL-controller-specific usage of HMAC
  DRBG for random numbers discussed in the [RNG documentation](../docs/rng.md)
* `scewl.{c,h}`: The SCEWL send/receive functions were moved here to clean up
  `controller.c`
* `timers.{c,h}`: Contains the hardware timer configuration and usage code for
  DTLS timeouts and SCUM sync request re-sends.
* `lm32/controller.ld`: The linker script to set up memory regions. The Flash
  memory region for the Flash buffers is set up here.
* `mbedtls/`: MbedTLS submodule
* `mbedtls_custom/`: Custom modifications to MbedTLS.
* `masked-aes-c`: [Masked AES implementation](https://github.com/CENSUS/masked-aes-c)
  for side-channel protection.