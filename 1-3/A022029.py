import socket
import sys
import struct
# The following libraries should be installed before executing
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Produce client private key and export as PEM file
# 1. Generate the RSA Private Key ( the RSA PRivate key is a object containing both private key and public key )
# The following 2nd and 3rd step are not necessary to be done
	# 2. Transform the RSA Private key to it's PEM format
	# 3. Write the PEM format into the PEM file
private_key = rsa.generate_private_key(
     public_exponent=65537,
     key_size=1024,
     backend=default_backend()
)


# Produce client public key and export as PEM file
# 1. Get the RSA Public Key from the object - RSA PRivate key
# 2. Transform the RSA Public key to it's PEM format
# 3. Write the PEM format into the PEM file

public_key = private_key.public_key()
pem = public_key.public_bytes(
     encoding=serialization.Encoding.PEM,
     format=serialization.PublicFormat.SubjectPublicKeyInfo
)
pem.splitlines()[0]
f = open('my_public_key.pem','wb')
f.write(pem)
f.close();

# Construct a TCP socket
HOST, PORT = "140.113.194.88", 45000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
	# Connect to the server
	sock.connect((HOST, PORT))
	
	# Send hello to server
	# 1. Send the size in byte of "hello" to Server
	msg_size = len("hello")
	byte_msg_size = struct.pack("i", msg_size)
	print(byte_msg_size)
	sock.sendall( byte_msg_size )
	# 2. Send the "hello" string to Server
	sock.sendall(bytes("hello", 'utf-8'))


	# Receive Hello From server
	msg_size = struct.unpack("i", sock.recv(4))
	received = str(sock.recv(int(msg_size[0])), "utf-8")
	print(received)

	# Receive Server public pem file
	# 1. Receive the size in byte of Server Public Key's PEM file from Server
	#msg_size = struct.unpack("i", sock.recv(4))
	# 2. Receive Server Public Key's PEM file from Server
	#received = sock.recv(int(msg_size[0]))
	# 3. Write the Server's Public Key PEM file and store it
	#ff = open('ta_public_key.pem','wb')
	#ff.write(received)

	# Send public pem file to server
	# 1. Read the Public Key's PEM file
	with open("my_public_key.pem", "rb") as key_file:
	     my_public_key_byte = key_file.read()

	# 1. Send the size in byte of Public Key's PEM file to Server
	msg_size = len(my_public_key_byte)
	byte_msg_size = struct.pack("i", msg_size)
	sock.sendall(byte_msg_size)
	# 2. Send Public Key's PEM file to Server 
	sock.sendall(my_public_key_byte)


	# Receive AES Session key
	msg_size = struct.unpack("i", sock.recv(4))
	received = sock.recv(int(msg_size[0]))

	AES_SESSION_KEY = private_key.decrypt(
	     received,
	     padding.OAEP(
	        mgf=padding.MGF1(algorithm=hashes.SHA1()),
	        algorithm=hashes.SHA1(),
	        label= b""
	    )
	)
	print(AES_SESSION_KEY)


	# Receive IV 
	msg_size = struct.unpack("i", sock.recv(4))
	received = sock.recv(int(msg_size[0]))

	IV = private_key.decrypt(
	     received,
	     padding.OAEP(
	        mgf=padding.MGF1(algorithm=hashes.SHA1()),
	        algorithm=hashes.SHA1(),
	        label= b""
	    )
	)
	print(IV)

	# Encrpt my ID

	cipher = Cipher(algorithms.AES(AES_SESSION_KEY), modes.CBC(IV), backend=default_backend())
	encryptor = cipher.encryptor()

	#padder = padding.PKCS7(128).padder()
	#padded_data = padder.update(b"A022029")
	#padded_data += padder.finalize()

	mid = b'A022029'
	toPad = (128 - ((len(mid)*8) % 128))/8
	x = ''
	i = toPad
	while i>0:
		x = x + '\0'
		i = i-1
	print(toPad)

	mid += bytes(x,'utf-8')


	print(mid , ' ' , len(mid))
	#print(padded_data,' ',len(padded_data))


	ciphertext = encryptor.update(mid) + encryptor.finalize()
	msg_size = len(ciphertext)
	byte_msg_size = struct.pack("i", msg_size)
	sock.sendall(byte_msg_size)
	sock.sendall(ciphertext)

	


	# Receive encrypted magic number
	# 1. Receive the size of encrypted magic bnumber from Server
	msg_size = struct.unpack("i", sock.recv(4))
	# 2. Receive encrypted magic bnumber from Server
	received = sock.recv(int(msg_size[0]))
	# 3. Decrypt the encrypted magic bnumber by client's RSA Private Key
	decryptor = cipher.decryptor()
	plaintext = decryptor.update(received) + decryptor.finalize()
	print('plaintext:',plaintext)
	#unpadder = padding.PKCS7(128).unpadder()
	#data = unpadder.update(plaintext)
	#data = data + unpadder.finalize()
	#print('data:',data)
	# MAY NEED PADDING?????????

	# Receive Bye
	# 1. Receive the size in byte of bye-message from Server
	msg_size = struct.unpack("i", sock.recv(4))
	# 2. Receive bye-message from Server
	received = str(sock.recv(int(msg_size[0])), "utf-8")

	print(received)
