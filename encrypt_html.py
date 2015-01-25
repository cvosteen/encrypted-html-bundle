from __future__ import unicode_literals
import base64, os.path, sys

# Python 2/3 compatibility
if sys.version_info[0] == 2:
	input = raw_input
	str = unicode

	old_bytes = bytes
	def new_bytes(s, enc=None):
		if enc: 
			return bytearray(s, enc)
		else:
			return bytearray(s)
	bytes = new_bytes


# Galois Field Operations

def GF_Double(n):
	'''
	Returns a number in the Galois Field GF(2^8) Doubled.
	Each polynomial power of x is represented by a bit.
	Thus to double, rotate the bits to the left.
	After that, the total must be mod x^8 + x^4 + x^3 + x + 1
	which is represented by the bits 0x11B.

	If the 9th bit is 1 xor this number with the mod bits.
	'''
	return n << 1 if n < 128 else (n << 1) ^ 0x11B


rcon = bytes([0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
	0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5])


def GF_Multiply(a, b):
	'''
	Muliplies the polynomials in the Galois Field GF(2^8).  
	Since each term in a must be multipled by each term in b,
	use bit shifting tricks to simulate this.
	'''
	accum = 0
	while a > 0:
		if a & 1:
			accum ^= b
		b = GF_Double(b)
		a >>= 1
	return accum

sbox = bytes([
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
	])

# Operations needed for Key Expansion

def addBytes(a, b):
	'''
	Perform an XOR on each item in a with each corresponding item
	in b.  Thus a new list of [a[0] ^ b[0], a[1] ^ b[1], ... ]
	will be returned.  The longer of the two lists, if any will
	be truncated.
	'''
	return bytes(a[i] ^ b[i] for i in range(min(len(a), len(b)))) 


def rotate_bytes(b, reps = 1):
	'''
	Takes a list and rotates it forward
	so that the first list item moves to the end
	and the remaining items move back 1.

	Defaults to a shift of 1 byte.
	'''
	if reps > 0:
		for _ in range(reps):
			b = b[1:] + b[:1]
	else:
		for _ in range(-reps):
			b = b[-1:] + b[:-1]

	return b


def keyExpansion(key):
	max_bytes = 240
	block_size = len(key) 
	expon_iter = 1
	exkey = bytearray(key)

	while len(exkey) < max_bytes:
		temp = bytearray(sbox[b] for b in rotate_bytes(exkey[-4:]))
		temp[0] ^= rcon[expon_iter]
		expon_iter += 1
		exkey += addBytes(temp, exkey[-block_size:])

		for _ in range(3):
			exkey += addBytes(exkey[-4:], exkey[-block_size:])

		temp = [sbox[b] for b in exkey[-4:]]
		exkey += addBytes(temp, exkey[-block_size:])

		for _ in range(3):
			exkey += addBytes(exkey[-4:], exkey[-block_size:])

	return exkey[:max_bytes]


# Operations needed for Encryption

def transpose(block):
	'''
	Given a 4x4 block of bytes, transpose from row order first
	to column order first.
	'''
	result = bytearray([0] * 16)
	for col in range(4):
		for row in range(4):
			result[(4*row) + col] = block[(4*col) + row]
		
	return result


def mixColumn(a):
	'''
	Perform the matrix multiplication over GF(2^8)

	[ b0 ]   [ 2 3 1 1 ][ a0 ]
	[ b1 ]   [ 1 2 3 1 ][ a1 ]
	[ b2 ] = [ 1 1 2 3 ][ a2 ]
	[ b3 ]   [ 3 1 1 2 ][ a3 ]

	'''
	return bytes([
		GF_Multiply(2, a[0]) ^ GF_Multiply(3, a[1]) ^ a[2] ^ a[3],
		a[0] ^ GF_Multiply(2, a[1]) ^ GF_Multiply(3, a[2]) ^ a[3],
		a[0] ^ a[1] ^ GF_Multiply(2, a[2]) ^ GF_Multiply(3, a[3]),
		GF_Multiply(3, a[0]) ^ a[1] ^ a[2] ^ GF_Multiply(2, a[3])
	])


# Main Steps for Encryption

def subBytes(state):
	return bytes(sbox[b] for b in state)

def shiftRows(state):
	return               state[ 0: 4] + \
		rotate_bytes(state[ 4: 8]) + \
		rotate_bytes(state[ 8:12], 2) + \
		rotate_bytes(state[12:16], 3)

def mixColumns(state):
	state = transpose(state)
	state = mixColumn(state[ 0: 4]) + \
		mixColumn(state[ 4: 8]) + \
		mixColumn(state[ 8:12]) + \
		mixColumn(state[12:16])
	return transpose(state)


# Encryption

def encrypt_data(data, key):
	'''Encrypts data with the given key.  Parameters and return value are bytes.'''
	num_rounds = 14
	cipher_data = bytearray()

	exkey = keyExpansion(key)

	cbc = bytes([0] * 16)

	for offset in range((len(data)+15)//16):
		state = data[offset*16:offset*16 + 16]
		if len(state) < 16:
			state += bytearray([0] * (16 - len(state)))
		state = addBytes(cbc, state)

		# Initial Round
		roundKey = exkey[:16]
		state = addBytes(roundKey, state)

		# Main Rounds
		for r in range(num_rounds - 1):
			roundKey = exkey[r*16+16:r*16+32]
			state = addBytes(roundKey, mixColumns(shiftRows(subBytes(state))))
		
		# Final Round
		roundKey = exkey[-16:]
		state = addBytes(roundKey, shiftRows(subBytes(state)))

		cipher_data += state
		cbc = state

	return bytes(cipher_data)

def embed_in_html(data, data_len, output_filename, template_file, html_file):
	'''Takes encrypted data and embeds it in the self-decrypting html file'''
	i = open(template_file, 'rb')
	o = open(html_file, 'wb')
	
	template = str(i.read(), 'utf-8')
	i.close()

	template %= (str(base64.b64encode(data), 'utf-8'), data_len, output_filename, output_filename)
	o.write(bytes(template, 'utf-8'))
	o.close()


if __name__ == '__main__':

	if len(sys.argv) < 2:
		print("USAGE:\n\npython encrypt_html.py <filename>\n")
		sys.exit()
	input_filename = sys.argv[1]

	password = bytes(input('Password: '), 'ascii')

	# Always make the key 256 bytes (Hashing might be a better solution in a future release)
	key = password[:32]
	if len(key) < 32:
		key += b'\0' * (32 - len(key))
	
	i = open(input_filename, 'rb')
	data = bytes(i.read())
	i.close()

	print('Encrypting...')
	encrypted = encrypt_data(data, key)

	current_path = os.path.dirname(os.path.realpath(sys.argv[0]))
	template_file = os.path.join(current_path, 'template.html')
	output_file = os.path.join(current_path, 'encrypted.html')
	embed_in_html(encrypted, len(data), os.path.basename(input_filename), template_file, output_file)


