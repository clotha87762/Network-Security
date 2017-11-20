import socket
import sys
import struct
import json
import binascii
import os.path
# The following libraries should be installed before executing
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes



myID = True;

# Produce client private key and export as PEM file
# 1. Generate the RSA Private Key ( the RSA PRivate key is a object containing both private key and public key )
# The following 2nd and 3rd step are not necessary to be done
	# 2. Transform the RSA Private key to it's PEM format
	# 3. Write the PEM format into the PEM file

if os.path.exists("my_private_key.pem") == False:

	private_key = rsa.generate_private_key(
	     public_exponent=65537,
	     key_size=1024,
	     backend=default_backend()
	)

	with open("my_private_key.pem", "wb") as f:
	     f.write(private_key.private_bytes(
	         encoding=serialization.Encoding.PEM,
	         format=serialization.PrivateFormat.TraditionalOpenSSL,
	         encryption_algorithm=serialization.NoEncryption(),
	     ))
else:
	with open("my_private_key.pem", "rb") as f:
    	 private_key = serialization.load_pem_private_key(
        	 f.read(),
         	password=None,
         	backend=default_backend()
     	 )

# Produce client public key and export as PEM file
# 1. Get the RSA Public Key from the object - RSA PRivate key
# 2. Transform the RSA Public key to it's PEM format
# 3. Write the PEM format into the PEM file

public_key = private_key.public_key()

if os.path.exists("my_public_key.pem")==False:

	pem = public_key.public_bytes(
	     encoding=serialization.Encoding.PEM,
	     format=serialization.PublicFormat.SubjectPublicKeyInfo
	)
	pem.splitlines()[0]
	f = open('my_public_key.pem','wb')
	f.write(pem)
	f.close();

# Construct a TCP socket
HOSTA, PORTA = "140.113.194.88", 20000
HOSTB, PORTB = "140.113.194.88", 20500
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sockA:
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sockB:
		

		flag = False
		


		if os.path.exists("certificate_pem.pem"):
			with open("certificate_pem.pem", "rb") as f:
				print("found pem")
				csr_byte = f.read()
				flag = True
				certificate_pem = x509.load_pem_x509_certificate(csr_byte, default_backend())
				certificate_pem_len = len(csr_byte)


		if flag == False :
			# Connect to the server
			sockA.connect((HOSTA, PORTA))
				
			# Send hello to server
			# 1. Send the size in byte of "hello" to Server
			msg_size = len("A022029")
			byte_msg_size = struct.pack("i", msg_size)
			#print(byte_msg_size)
			sockA.sendall( byte_msg_size )
			# 2. Send the "hello" string to Server
			sockA.sendall(bytes("A022029", 'utf-8'))


			# Receive Hello From server
			msg_size = struct.unpack("i", sockA.recv(4))
			received = str(sockA.recv(int(msg_size[0])), "utf-8")
			print(received)


			# Send CSR to CA
			csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"A022029")])).sign(private_key, hashes.SHA256(), default_backend())

	 		#with open("csr.pem", "wb") as f:
			#	 f.write(csr.public_bytes(serialization.Encoding.PEM))


			csr_byte  = csr.public_bytes(serialization.Encoding.PEM)
			certificate_pem_len = len(csr_byte)

			msg_size = len(csr_byte)
			byte_msg_size = struct.pack("i", msg_size)
			#print(byte_msg_size)
			sockA.sendall( byte_msg_size )
			# 2. Send csr to server
			sockA.sendall(csr_byte)


			# Receive PEM File From server
			msg_size = struct.unpack("i", sockA.recv(4))
			certificate_pem = sockA.recv(int(msg_size[0]))

			with open("certificate_pem.pem", "wb") as f:
				f.write(certificate_pem)


			# Receive bye From CA
			msg_size = struct.unpack("i", sockA.recv(4))
			received = str(sockA.recv(int(msg_size[0])),"utf-8")
			print(received)

			sockA.close()

			with open("certificate_pem.pem", "rb") as f:
				print("found pem")
				csr_byte = f.read()
				flag = True
				certificate_pem = x509.load_pem_x509_certificate(csr_byte, default_backend())
				certificate_pem_len = len(csr_byte)



		sockB.connect((HOSTB, PORTB))
		# Send ID to Game Downloader

		msg_size = len("A022029")
		byte_msg_size = struct.pack("i", msg_size)
		#print(byte_msg_size)
		sockB.sendall( byte_msg_size )
		# 2. Send the "hello" string to Server
		sockB.sendall(bytes("A022029", 'utf-8'))

		# Receive Hello From Game Downloader
		msg_size = struct.unpack("i", sockB.recv(4))
		received = str(sockB.recv(int(msg_size[0])), "utf-8")
		print(received)

		#Sedn certificated_pem to Game Downloader
		msg_size = certificate_pem_len
		byte_msg_size = struct.pack("i", msg_size)
		#print(byte_msg_size)
		sockB.sendall( byte_msg_size )
		# 2. Send the "hello" string to Server
		sockB.sendall(csr_byte)

		# Receive PASS From Game Downloader
		msg_size = struct.unpack("i", sockB.recv(4))
		received = str(sockB.recv(int(msg_size[0])), "utf-8")
		print(received)

		# Receive Session key & IV From server

		# Receive AES Session key
		msg_size = struct.unpack("i", sockB.recv(4))
		received = sockB.recv(int(msg_size[0]))

		AES_SESSION_KEY = private_key.decrypt(
			received,
			padding.OAEP(
			    mgf=padding.MGF1(algorithm=hashes.SHA1()),
			    algorithm=hashes.SHA1(),
			    label=None
			)
		)
		print(AES_SESSION_KEY)


		# Receive IV 
		msg_size = struct.unpack("i", sockB.recv(4))
		#print("iv:",msg_size)
		received = sockB.recv(int(msg_size[0]))
		IV = private_key.decrypt(
			received,
			padding.OAEP(
			    mgf=padding.MGF1(algorithm=hashes.SHA1()),
			    algorithm=hashes.SHA1(),
			    label=None
			)
		)
		print(IV)


		# Receive Game Binary From Server
		msg_size = struct.unpack("i", sockB.recv(4))
		game_size = int(msg_size[0])
		print("game size: ",int(msg_size[0]))
		game_binary = b""
		while True:  
		    a = sockB.recv(1)  
		    if not len(a):break
		    game_binary += a 

		print("buffsize:",len(game_binary))
		#game_binary = sockB.recv(int(msg_size[0]))
		
		# Send bye to server
		msg_size = len("bye")
		byte_msg_size = struct.pack("i", msg_size)
		#print(byte_msg_size)
		sockB.sendall( byte_msg_size )
		# 2. Send the "hello" string to Server
		sockB.sendall(bytes("bye", 'utf-8'))

		# Decrypt Game Binary
		

		cipher = Cipher(algorithms.AES(AES_SESSION_KEY), modes.CBC(IV), backend=default_backend())
		decryptor = cipher.decryptor()
		decrypted_game = decryptor.update(game_binary) + decryptor.finalize()

		with open("game", "wb") as f:
				f.write(decrypted_game)

		
