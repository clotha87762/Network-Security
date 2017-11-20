import socket
import sys
import struct
import json
import binascii
# The following libraries should be installed before executing
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes




myID = True;

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
HOSTA, PORTA = "140.113.194.88", 50000
HOSTB, PORTB = "140.113.194.88", 50500
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sockA:
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sockB:
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sockC:
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


			# Send Hello to Server B
			sockB.connect((HOSTB, PORTB))
			
			# Send hello to server
			# 1. Send the size in byte of "hello" to Server
			msg_size = len("hello")
			byte_msg_size = struct.pack("i", msg_size)
			#print(byte_msg_size)
			sockB.sendall( byte_msg_size )
			# 2. Send the "hello" string to Server
			sockB.sendall(bytes("hello", 'utf-8'))


			# Receive PEM File From serverB
			msg_size = struct.unpack("i", sockB.recv(4))
			received = sockB.recv(int(msg_size[0]))
			

			ta_public_key = serialization.load_pem_public_key(
		     received,
		   	 backend=default_backend()
			)




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
			sockA.sendall(byte_msg_size)
			# 2. Send Public Key's PEM file to Server 
			sockA.sendall(my_public_key_byte)


			# Receive AES Session key
			msg_size = struct.unpack("i", sockA.recv(4))
			received = sockA.recv(int(msg_size[0]))

			AES_SESSION_KEY_A = private_key.decrypt(
			     received,
			     padding.OAEP(
			        mgf=padding.MGF1(algorithm=hashes.SHA1()),
			        algorithm=hashes.SHA1(),
			        label=None
			    )
			)
			#print(AES_SESSION_KEY_A)


			# Receive IV 
			msg_size = struct.unpack("i", sockA.recv(4))
			#print("iv:",msg_size)
			received = sockA.recv(int(msg_size[0]))

			IV_A = private_key.decrypt(
			     received,
			     padding.OAEP(
			        mgf=padding.MGF1(algorithm=hashes.SHA1()),
			        algorithm=hashes.SHA1(),
			        label=None
			    )
			)
			print(IV_A)


			# Receive Request Message
			msg_size = struct.unpack("i", sockA.recv(4))
			received = sockA.recv(int(msg_size[0]))
			encrypted_msg_1 = received

			# Encrpt my ID

			cipherA = Cipher(algorithms.AES(AES_SESSION_KEY_A), modes.CBC(IV_A), backend=default_backend())
			encryptorA = cipherA.encryptor()
			decryptorA = cipherA.decryptor()
			req_msg = decryptorA.update(received) + decryptorA.finalize()

			print()
			print("req_msg",req_msg)

			mstr = str(req_msg,"utf-8")
			strlen = len(mstr)
			while mstr[strlen-1]=='\0':
				strlen = strlen-1

			json_str = mstr[0:strlen]
			print()
			#print("json:L",json_str)
			json_data = json.loads(json_str)
			#print("jsondata:",json_data)
			json_data['Account_ID'] = "A022029"
			digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
			digest.update(b"A022029")
			code = digest.finalize()
			json_data['Authentication_Code'] = str(binascii.hexlify(code),"utf=8")

			final_obj = json.dumps(json_data)
		
			#print('final_obj: ',final_obj)
			#print(req_msg)

			
			# Send AES Session Key

			encrypted_AES_KEY = ta_public_key.encrypt(
		    	AES_SESSION_KEY_A,
		     	padding.OAEP(
	         		mgf=padding.MGF1(algorithm=hashes.SHA1()),
	         		algorithm=hashes.SHA1(),
	         		label= b""
		     	)
			)

			msg_size = len(encrypted_AES_KEY)
			byte_msg_size = struct.pack("i", msg_size)
			sockB.sendall(byte_msg_size)
			sockB.sendall(encrypted_AES_KEY)

			encrypted_IV = ta_public_key.encrypt(
		    	IV_A,
		     	padding.OAEP(
	         		mgf=padding.MGF1(algorithm=hashes.SHA1()),
	         		algorithm=hashes.SHA1(),
	         		label= b""
		     	)
			)
			msg_size = len(encrypted_IV)
			byte_msg_size = struct.pack("i", msg_size)
			sockB.sendall(byte_msg_size)
			sockB.sendall(encrypted_IV)

			# Send Request to Server B  (myID)
			if myID==True:
				mid = bytes(final_obj,'utf-8')
				#print("len:",len(mid))
				toPad = (128 - ((len(mid)*8) % 128))/8
				x = ''
				i = toPad
				while i>0:
					x = x + '\0'
					i = i-1
				#print(toPad)

				mid += bytes(x,'utf-8')

				#print("len:",len(req_msg),"  ",req_msg)
				#print("MID :",len(mid),"  ",mid)
				cipherC = Cipher(algorithms.AES(AES_SESSION_KEY_A), modes.CBC(IV_A), backend=default_backend())
				encryptorC = cipherC.encryptor()
				decryptorC = cipherC.decryptor()
				ciphertext = encryptorA.update(mid) + encryptorA.finalize()

				msg_size = len(ciphertext)
				byte_msg_size = struct.pack("i", msg_size)
				sockB.sendall(byte_msg_size)
				sockB.sendall(ciphertext)

				msg_size = struct.unpack("i", sockB.recv(4))
				received = sockB.recv(int(msg_size[0]))

				
				response_msg2 = decryptorC.update(received) + decryptorC.finalize()
				print("response msg of my ID:",response_msg2)


				#Receive Bye from B
				msg_size = struct.unpack("i", sockB.recv(4))
				#print("msg_size",msg_size)
				received = str(sockB.recv(int(3)), "utf-8")
				#print(received)

				sockB.close()
				sockC.connect((HOSTB,PORTB))

				# Send hello to server
				# 1. Send the size in byte of "hello" to Server
				msg_size = len("hello")
				byte_msg_size = struct.pack("i", msg_size)
				#print(byte_msg_size)
				sockC.sendall( byte_msg_size )
				# 2. Send the "hello" string to Server
				sockC.sendall(bytes("hello", 'utf-8'))


				# Receive PEM File From serverB
				msg_size = struct.unpack("i", sockC.recv(4))
				received = sockC.recv(int(msg_size[0]))
				

				ta_public_key2 = serialization.load_pem_public_key(
			     received,
			   	 backend=default_backend()
				)

				encrypted_AES_KEY = ta_public_key2.encrypt(
		    		AES_SESSION_KEY_A,
		     		padding.OAEP(
	         			mgf=padding.MGF1(algorithm=hashes.SHA1()),
	         			algorithm=hashes.SHA1(),
	         			label= b""
		     		)
				)

				msg_size = len(encrypted_AES_KEY)
				byte_msg_size = struct.pack("i", msg_size)
				sockC.sendall(byte_msg_size)
				sockC.sendall(encrypted_AES_KEY)

				encrypted_IV = ta_public_key2.encrypt(
			    	IV_A,
			     	padding.OAEP(
		         		mgf=padding.MGF1(algorithm=hashes.SHA1()),
		         		algorithm=hashes.SHA1(),
		         		label= b""
			     	)
				)
				msg_size = len(encrypted_IV)
				byte_msg_size = struct.pack("i", msg_size)
				sockC.sendall(byte_msg_size)
				sockC.sendall(encrypted_IV)




			#Send Alice's original request to Bob
			msg_size = len(encrypted_msg_1)
			byte_msg_size = struct.pack("i", msg_size)
			sockC.sendall(byte_msg_size)
			sockC.sendall(encrypted_msg_1)


			# Receive Response Message
			cipherB = Cipher(algorithms.AES(AES_SESSION_KEY_A), modes.CBC(IV_A), backend=default_backend())
			encryptorB = cipherB.encryptor()
			decryptorB = cipherB.decryptor()

			msg_size = struct.unpack("i", sockC.recv(4))
			received = sockC.recv(int(msg_size[0]))

			encrypted_response = received
			response_msg = decryptorB.update(received) + decryptorB.finalize()
			print("response msg of Alice's ID:",response_msg)


			#Receive Bye from B
			msg_size = struct.unpack("i", sockC.recv(4))
			#print("msg_size",msg_size)
			received = str(sockC.recv(int(3)), "utf-8")
			print(received)





			# Send response to Alice
			msg_size = len(encrypted_response)
			byte_msg_size = struct.pack("i", msg_size)
			sockA.sendall(byte_msg_size)
			sockA.sendall(encrypted_response)

			msg_size = len("bye")
			byte_msg_size = struct.pack("i", msg_size)
			sockA.sendall(byte_msg_size)
			sockA.sendall(bytes("bye", 'utf-8'))

			#padder = padding.PKCS7(128).padder()
			#padded_data = padder.update(b"A022029")
			#padded_data += padder.finalize()
			
			#mid = b'A022029'
			#toPad = (128 - ((len(mid)*8) % 128))/8
			#x = ''
			#i = toPad
			#while i>0:
			#	x = x + '\0'
			#	i = i-1
			#print(toPad)

			#mid += bytes(x,'utf-8')


			#print(mid , ' ' , len(mid))
			#print(padded_data,' ',len(padded_data))


			#ciphertext = encryptor.update(mid) + encryptor.finalize()
			#msg_size = len(ciphertext)
			#byte_msg_size = struct.pack("i", msg_size)
			#sock.sendall(byte_msg_size)
			#sock.sendall(ciphertext)

			


			# Receive encrypted magic number
			# 1. Receive the size of encrypted magic bnumber from Server
			#msg_size = struct.unpack("i", sock.recv(4))
			# 2. Receive encrypted magic bnumber from Server
			#received = sock.recv(int(msg_size[0]))
			# 3. Decrypt the encrypted magic bnumber by client's RSA Private Key
			#decryptor = cipher.decryptor()
			#plaintext = decryptor.update(received) + decryptor.finalize()
			#print('plaintext:',plaintext)
			#unpadder = padding.PKCS7(128).unpadder()
			#data = unpadder.update(plaintext)
			#data = data + unpadder.finalize()
			#print('data:',data)
			# MAY NEED PADDING?????????

			# Receive Bye
			# 1. Receive the size in byte of bye-message from Server
			#msg_size = struct.unpack("i", sock.recv(4))
			# 2. Receive bye-message from Server
			#received = str(sock.recv(int(msg_size[0])), "utf-8")

			#print(received)
