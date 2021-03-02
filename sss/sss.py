#!/usr/bin/python3

# 2021 Collegiate eCTF
# SCEWL Security Server
# Ben Janis
#
# (c) 2021 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
# This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
# and may not meet MITRE standards for quality. Use this code at your own risk!

from contextlib import suppress
from datetime import datetime, timedelta
from secrets import token_bytes
import socket
import select
import struct
import argparse
import logging
import os

from mbedtls import hashlib, pk, tls, x509
from mbedtls.exceptions import TLSError


SSS_IP = 'localhost'
SSS_ID = 1
SCEWL_MTU = 1000
MAX_FRAG_LENGTH = 935

SCUM_KEY_LENGTH = 32
SCUM_SALT_LENGTH = 12

# mirroring scewl enum at scewl.c:4
BAD_REQUEST, REG, DEREG = -1, 0, 1

MAIN_LOOP_MIN_FREQUENCY = None
DEBUG_LEVEL = 1

logging.basicConfig(level=logging.DEBUG)


def block(callback, *args, **kwargs):
	while True:
		with suppress(tls.WantReadError, tls.WantWriteError):
			return callback(*args, **kwargs)


class ScewlSocket(tls.TLSWrappedSocket):
	def __init__(self, socket, buffer):
		self._socket = socket
		self._buffer = buffer
		super().__init__(socket, buffer)

	def _recv_scewl(self):
		tgt_id = None
		length = 0
		while tgt_id != SSS_ID or length < 0:
			bytes = b''
			while bytes != b'C':
				while bytes != b'S':
					bytes = self._socket.recv(1)
				bytes = self._socket.recv(1)
			scewl_header = self._socket.recv(6, socket.MSG_WAITALL)
			tgt_id, self.peername, length = struct.unpack('<HHH', scewl_header)
		scewl_payload = self._socket.recv(length, socket.MSG_WAITALL)
		self._buffer.receive_from_network(scewl_payload)
		logging.debug(f'Received SCEWL packet from {self.peername} with payload length {length}.')

	def recv(self, bufsize, flags=0):
		data, _ = self.recvfrom(bufsize, flags)
		return data

	def recvfrom(self, bufsize, flags=0):
		if flags != 0:
			raise Exception(f'Flags not supported. Flags passed: {flags}')
		self._recv_scewl()
		self._send_scewl()
		return self._buffer.read(bufsize), str(self.peername)

	def _send_scewl(self):
		encrypted = self._buffer.peek_outgoing(SCEWL_MTU)
		if len(encrypted) == 0:
			return
		self._socket.sendall(struct.pack('<2sHHH', b'SC', self.peername, SSS_ID, len(encrypted)) + encrypted)
		self._buffer.consume_outgoing(len(encrypted))
		logging.debug(f'Sent SCEWL packet to {self.peername} with payload length {len(encrypted)}.')

	def send(self, message, flags=0):
		self.sendall(message, flags)

	def sendall(self, message, flags=0):
		if flags != 0:
			raise Exception(f'Flags not supported. Flags passed: {flags}')
		bytes_sent = 0
		while len(message) > MAX_FRAG_LENGTH:
			self._buffer.write(message[:MAX_FRAG_LENGTH])
			self._send_scewl()
			message = message[MAX_FRAG_LENGTH:]
			bytes_sent += MAX_FRAG_LENGTH
		if len(message) > 0:
			self._buffer.write(message)
			self._send_scewl()
			bytes_sent += len(message)
		self._recv_scewl()
		return bytes_sent

	def getpeername(self):
		if hasattr(self, 'peername'):
			return str(self.peername)
		data = b''
		while len(data) != 6:
			data = self._socket.recv(6, socket.MSG_PEEK)
		magic_bytes, _, src_id = struct.unpack('<2sHH', data)
		if magic_bytes == b'SC':
			self.peername = src_id
			return str(self.peername)
		return None

	def getsockname(self):
			return str(SSS_ID)

	def _do_handshake_step(self):
		self._recv_scewl()
		try:
			state = self._buffer._do_handshake_step()
		finally:
			self._send_scewl()
		return state

	def do_handshake(self):
		self._recv_scewl()
		try:
			self._buffer.do_handshake()
		finally:
			self._send_scewl()


class Device:
	def __init__(self, sss, conn, addr):
		self.sss = sss
		self.conn = conn
		self.addr = addr
		self.handshake_complete = False
		self.registered = False
		self.runtime_cert = None

	def new_conn(self, conn):
		self.conn = conn

	def disconnect(self):
		self.conn._buffer.shutdown()
		self.handshake_complete = False

	def handle(self):
		if self.handshake_complete:
			self.handle_transaction()
			self.disconnect()
		else:
			self.handshake()

	def handshake(self):
		self.conn._buffer.context._set_hostname(f'{self.conn.getpeername()}_PROVISION')
		self.conn.setcookieparam(self.conn.getpeername().encode("ascii"))
		try:
			block(self.conn.do_handshake)
			logging.debug(f'Finished handshake with {self.conn.getpeername()}.')
			self.handshake_complete = True
		except tls.HelloVerifyRequest:
			logging.debug(f'Hello verification requested.')
		except TLSError:
			logging.exception(f'Handshake with {self.conn.getpeername()} failed.')
			self.disconnect()

	def handle_transaction(self):
		logging.debug(f'Handling transaction with client {self.addr}')

		# Receive request from client
		data = block(self.conn.recv, 4)
		dev_id, op = struct.unpack('<Hh', data)

		if dev_id != self.addr:
			logging.warn(f'Client {self.addr} sent request with dev_id {dev_id}. This is not allowed.')
			return

		# Process request
		resp = struct.pack('<HhHHH', self.addr, BAD_REQUEST, 0, 0, 0)
		if op == REG:
			if self.registered:
				logging.warning(f'Client {self.addr} requested to register when it is already registered.')
			else:
				resp = self.register()
				self.registered = True
				logging.info(f'Client {self.addr} registered.')
		elif op == DEREG:
			if self.registered:
				resp = self.deregister()
				self.registered = False
				logging.info(f'Client {self.addr} deregistered.')
			else:
				logging.warning(f'Client {self.addr} requested to deregister when it is not registered.')

		# Send response
		self.conn.send(resp)

		logging.debug(f'Finished transaction with client {self.addr}')

	def register(self):
		now = datetime.utcnow()
		key = pk.RSA()
		key.generate()
		csr = x509.CSR.new(key, f'CN={self.addr}', hashlib.sha256())
		self.runtime_cert = self.sss.runtime_ca_cert.sign(
			csr, self.sss.runtime_ca_key,
			not_before=now, not_after=now + timedelta(hours=8),
			serial_number=self.addr
		)
		ca_der = self.sss.runtime_ca_cert.export(format="DER")
		crt_der = self.runtime_cert.export(format="DER")
		pk_der = key.export_key(format="DER")

		sync_key = sss.scum_sync_key
		sync_salt = sss.scum_sync_salt
		data_key = sss.scum_data_key
		data_salt = sss.scum_data_salt

		first_sed = b'\x01' if (sss.reg_count == 0) else b'\x00'
		sss.reg_count += 1

		# SCUM keys/salts/sync indicator have fixed length
		return struct.pack('<HhHHHHHHHH', self.addr, REG, len(ca_der), len(crt_der), len(pk_der), \
											len(sync_key), len(sync_salt), len(data_key), len(data_salt), len(first_sed)) \
										+ ca_der + crt_der + pk_der + sync_key + sync_salt + data_key + data_salt + first_sed

	def deregister(self):
		self.runtime_cert = None
		sss.reg_count -= 1
		return struct.pack('<HhHHHHHHHH', self.addr, DEREG, 0, 0, 0, 0, 0, 0, 0, 0)


class SSS:
	def __init__(self, sockf):
		# Make sure the socket does not already exist
		try:
			os.unlink(sockf)
		except OSError:
			if os.path.exists(sockf):
				raise

		# Load provisioning CA certificate and key
		self.provision_ca_cert = x509.CRT.from_file('/secrets/sss/ca.crt')
		with open('/secrets/sss/ca.key', 'r') as keyfile:
			self.provision_ca_key = pk.RSA.from_buffer(x509.PEM_to_DER(keyfile.read()))

		# Generate runtime CA certificate and key
		now = datetime.utcnow()
		self.runtime_ca_key = pk.RSA()
		self.runtime_ca_key.generate()
		csr = x509.CSR.new(self.runtime_ca_key, "CN=SSS", hashlib.sha256())
		self.runtime_ca_cert = x509.CRT.selfsign(
			csr, self.runtime_ca_key,
			not_before=now, not_after=now + timedelta(hours=8),
			serial_number=0x1,
			basic_constraints=x509.BasicConstraints(ca=True, max_path_length=1)
		)

		# Trust store for registration
		trust_store = tls.TrustStore()
		trust_store.add(self.provision_ca_cert)

		# DTLS server configuration
		self.dtls_conf = tls.DTLSConfiguration(
			trust_store=trust_store,
			certificate_chain=([self.provision_ca_cert], self.provision_ca_key),
			validate_certificates=True
		)
		tls._set_debug_level(DEBUG_LEVEL)
		tls._enable_debug_output(self.dtls_conf)

		# Generate SCUM keys
		self.scum_data_key = token_bytes(SCUM_KEY_LENGTH)
		self.scum_data_salt = token_bytes(SCUM_SALT_LENGTH)
		self.scum_sync_key = token_bytes(SCUM_KEY_LENGTH)
		self.scum_sync_salt = token_bytes(SCUM_SALT_LENGTH)

		# Registered device count
		self.reg_count = 0

		# Socket
		self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind(sockf)

		self.devs = {}

	def start(self):
		timeout = 1 / MAIN_LOOP_MIN_FREQUENCY if MAIN_LOOP_MIN_FREQUENCY is not None else None
		self.sock.listen()
		logging.info('SSS started.')
		# Serve forever
		while True:
			sockets = [self.sock] + [dev.conn for dev in self.devs.values() if dev.conn is not None]
			readable, _, exceptional = select.select(sockets, [], sockets, timeout)
			if self.sock in exceptional:
				raise Exception(f'The SSS server socket {self.sock.getsockname()} failed.')
			for conn in exceptional:
				dev = next(dev for dev in self.devs if dev.conn == conn)
				dev.disconnect()
			if self.sock in readable:
				# Perform DTLS handshake with a newly-connected SED
				stream_conn, _ = self.sock.accept()
				buffers = tls.ServerContext(self.dtls_conf).wrap_buffers()
				conn = ScewlSocket(stream_conn, buffers)
				peername = int(conn.getpeername())
				if peername is not None:
					logging.debug(f'New connection from {peername}.')
					if peername in self.devs:
						self.devs[peername].new_conn(conn)
					else:
						self.devs[peername] = Device(self, conn, peername)
				readable.remove(self.sock)
			for conn in readable:
				# Handle request from an already-connected SED
				dev = next(dev for dev in self.devs.values() if dev.conn == conn)
				dev.handle()


def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('sockf', help='Path to socket to bind the SSS to')
	return parser.parse_args()


if __name__ == '__main__':
	args = parse_args()
	sss = SSS(args.sockf)
	sss.start()
