import hmac 
import time
import struct
import secrets
from hashlib import sha1
from base64 import b32decode, b32encode

def get_hotp_token(secret: str, intervals_no):
	'''Generates a HMAC-Based One-Time Password.'''
	key = b32decode(secret, casefold=True)
	msg = struct.pack(">Q", intervals_no)
	
	hmc = hmac.new(key, msg, sha1).digest()
	o = hmc[19] & 15
	hmc = (struct.unpack(">I", hmc[o:o + 4])[0] & 0x7fffffff) % 1000000
	
	return prefix_zeros(str(hmc))

def get_totp_token(secret: str, interval_length: int = 30):
	'''Generates a Time-Based One Time Password.'''
	return get_hotp_token(
		secret = normalize_secret(secret),
		intervals_no = int(time.time()) // interval_length
	)

def generate_random_secret(nbytes: int = 16):
	'''Generates a random secret key.'''
	return secrets.token_hex(nbytes).upper()

def normalize_secret(secret: str):
	'''Handles secret coming from user.'''
	# Removes spaces.
	secret = secret.strip().replace(' ', '')

	# Adds padding.
	if len(secret) % 8 != 0:
		secret += '=' * (8 - len(secret) % 8)

	# Returns base32 encoded and upper cased.
	return b32encode(secret.upper().encode())

def prefix_zeros(hmc: str):
	'''Puts zeros if missing.'''
	if len(hmc) < 6:
		hmc = '0' * (6 - len(hmc)) + hmc
	return hmc
