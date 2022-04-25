import socket
import os
from base64 import b64encode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import nacl.utils
import json

SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096 # send 4096 bytes each time step

# the ip address or hostname of the server, the receiver
host = "127.0.0.1"
# the port, let's use 5001
port = 65432
# the name of file we want to send, make sure it exists
filename = "D:\ITESO\Semestre 8\SeguridadEnRedes\cripto\SendEncryptedFile/fileToSend.txt"
# get the file size
filesize = os.path.getsize(filename)
print(f'fileSize: {filesize}')

# Obtener la llave usando PyNaCl
key = nacl.utils.random(32)
# Usar ChaCha20 con la llave
cipher = ChaCha20.new(key=key)

# Leer la informacion del archivo
with open(filename, 'rb') as NoEncryptedFile:
    fileData = NoEncryptedFile.read()

# Encryptar el contenido del archivo
cipherText = cipher.encrypt(fileData)

# Escribir el archivo con la informacion encriptada
with open(filename, 'wb') as writeEncryptedData:
    writtenData = writeEncryptedData.write(cipherText)

# nonce
nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(cipherText).decode('utf-8')
result = json.dumps({'nonce':nonce, 'ciphertext': ct})
print(result)


# create the client socket
s = socket.socket()
print(f"[+] Connecting to {host}:{port}")
s.connect((host, port))
print("[+] Connected.")

# send the filename and filesize
s.send(f"{filename}{SEPARATOR}{filesize}".encode())

# start sending the file
with open('fileToSend.txt', "rb") as f:
    while True:
        # read the bytes from the file
        bytes_read = f.read(BUFFER_SIZE)
        if not bytes_read:
            # file transmitting is done
            break
        # we use sendall to assure transimission in 
        # busy networks
        s.sendall(bytes_read)
# close the socket
s.close()