import select
import socket
import struct
import sys

OUTPUT_FILENAME = 'faa.log'

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sys.argv[1])

msgs = []
while select.select([sock], [], [], 60)[0]:
	# receive and unpack packet header
	hdr = b''
	while len(hdr) < 8:
		hdr += sock.recv(8 - len(hdr))
	_, tgt, src, ln = struct.unpack('<HHHH', hdr)

	# receive packet body
	data = b''
	while len(data) < ln:
		data += sock.recv(ln - len(data))
	msgs.append(f'{src}->{tgt} ({len(data)}B): {repr(data)}')

if msgs:
	with open(OUTPUT_FILENAME, 'wt') as output_file:
		for msg in msgs:
			print(msg, file=output_file)
