# System Buffers

## Buffer Utilization

The SCEWL controller uses a number of buffers in specific ways to allow the
implementation of both [DoS](dtls.md) and [SCUM](docs/scum.md) in the restricted
resources available on the Stellaris microcontroller. The system uses a
combination of buffers in SRAM and Flash to achieve the functionality.

All messages received from other SEDs and the SSS are stored in the 1000-byte
SRAM buffer `scewl_buf`. All messages sent with **DoS** and **SCUM** are
fragmented in 1000-byte segments, where we call the 1000-byte limit the SCEWL
Maximum Transmission Unit (MTU).

Messages received from the CPU or from the FAA channel, however, have no
enforceable rules for partitioning messages into the MTU, so the system reads
up to 16KB messages into Flash buffers, which are dedicated sections at the end
of Flash for holding maximum sized messages. Before reading a message from any
interface, the controller checks where that message should be stored. This is
achieved by only reading the SCEWL header to inform the program logic before
reading the message body.

In addition to the `scewl_buf` and Flash buffers, **DoS** and **SCUM** each have
their own MTU-sized buffers (staging buffers) for holding 
encrypted/decrypted data before being stored into a Flash buffer or sent to
another device. **SCUM** has two buffers: one for messages incoming from SCEWL,
and one for messages from the CPU that will be sent in the future. In the case
that another device defeats an SED during arbitration, the message-to-be-sent of
the defeated SED will remain in the out buffer until it is eventually sent.

## Flash Buffers

The system has separate Flash buffers for incoming/outgoing FAA messages,
outgoing DoS messages, and outgoing SCUM messages. These 16KB regions of Flash
are put into their own section to ensure the compiler does not attempt to store
any program code or initialization data in dedicated address ranges. The
effective locations of each buffer are given in the table below.

| Component Buffer | Address |
|------------------|---------|
| FAA Buf          | 0x30000 |
| DTLS Buf         | 0x34000 |
| SCUM In Buf      | 0x38000 |
| SCUM Out Buf     | 0x3C000 |

The Flash buffers are written to using the standard Flash control process of
erasing a full page, and then writing 32-bit words into the primed page. The
controller supports writing incomplete words into Flash buffers by holding any
bytes that do not fit into a full word in a temporary buffer. The next time a
write is made to the buffer, the temporarily stored bytes are written first.
When a system component (i.e. DoS, SCUM) is finished writing all data destined
for the CPU, the component commits the Flash buffer, which pads any remaining
bytes in the temporary buffer with zeroes, and programs the resulting word. This
functionality is implemented in [flash_buffers.c](../controller/flash_buffers.c)

*The authors acknowledge that use of Flash in this way would be infeasible on a
real physical device due to the longer Flash erase/write period, and the natural
write wear-out of Flash memory*