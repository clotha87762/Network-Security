import socket
import sys
import struct
# The following libraries should be installed before executing
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

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
HOST, PORT = "140.113.194.88", 30000

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

	# Receive Server public pem file
	# 1. Receive the size in byte of Server Public Key's PEM file from Server
	msg_size = struct.unpack("i", sock.recv(4))
	# 2. Receive Server Public Key's PEM file from Server
	received = sock.recv(int(msg_size[0]))
	# 3. Write the Server's Public Key PEM file and store it
	ff = open('ta_public_key.pem','wb')
	ff.write(received)

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

	# Send Student ID encrypted by Server's Public Key to Server
	# 1. Read Server Public Key's PEM file and get Server's Public Key
	
	#with open("ta_public_key.pem", "rb") as key_file2:
	##     ta_public_key = serialization.load_pem_public_key(
	#       key_file2.read(),
	#        backend=default_backend()
	#    )


	ta_public_key = serialization.load_pem_public_key(
	     received,
	   	 backend=default_backend()
	)
	# 2. Use Server's Public Key to encrypt Student ID
	message = b"A022029"	
	ciphertext = ta_public_key.encrypt(
	     message,
	     padding.OAEP(
         	mgf=padding.MGF1(algorithm=hashes.SHA1()),
         	algorithm=hashes.SHA1(),
         	label= b""
	     )
	)
	print("len:",len(ciphertext),"type:",type(ciphertext))
	# 3. Send the size in byte of ciphertext to Server
	msg_size = len(ciphertext)
	byte_msg_size = struct.pack("i", msg_size)
	sock.sendall(byte_msg_size)
	# 4. Send the ciphertext to Server
	sock.sendall(ciphertext)


	# Receive encrypted magic number
	# 1. Receive the size of encrypted magic bnumber from Server
	msg_size = struct.unpack("i", sock.recv(4))
	# 2. Receive encrypted magic bnumber from Server
	received = sock.recv(int(msg_size[0]))
	# 3. Decrypt the encrypted magic bnumber by client's RSA Private Key
	plaintext = private_key.decrypt(
	     received,
	     padding.OAEP(
	        mgf=padding.MGF1(algorithm=hashes.SHA1()),
	        algorithm=hashes.SHA1(),
	        label=None
	    )
	)
	
	print(plaintext)

	# Receive Bye
	# 1. Receive the size in byte of bye-message from Server
	msg_size = struct.unpack("i", sock.recv(4))
	# 2. Receive bye-message from Server
	received = str(sock.recv(int(msg_size[0])), "utf-8")

	print(received)
