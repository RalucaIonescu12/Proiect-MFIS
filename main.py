from PIL import Image
import hashlib
import os
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def pad(data):
    block_size = 16
    padding = block_size - (len(data) % block_size)
    return data + bytes([padding] * padding)

def unpad(data):
    padding = data[-1]
    return data[:-padding]

def encrypt(data, key):
    data = pad(data)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def decrypt(data, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    return unpad(decrypted_data)

key = b'\xae:\xa2N\x15\x1c0\xc8\xc2\xe0,\xba\x02\xa9\xc6*\x7fx\xf5\x8f,\xf7\xa1\xbf\\l\xa9+\x8f\xbc\xb0\xfc'
files = [f for f in os.listdir("imagini")]
for f in files[1:]:
    with open("imagini/"+f, 'rb') as file:
        image_data = file.read()
        encrypted_data = encrypt(image_data, key)
    with open("imagini/"+f, 'wb') as file:
        file.write(encrypted_data)

headers_hashed=[
"0743797ca76e37b8c04c0f1e9f1525d5",
   "c3e83e5f5470870cc95b9ca892264cd3",
  "c3e83e5f5470870cc95b9ca892264cd3",
   "b076791c37867ae7e520a9f26cd80af1"
]
headers=[]

def md5_hash(header):

    header_bytes = header.encode('utf-8')
    md5_hash_object = hashlib.md5()
    md5_hash_object.update(header_bytes)
    hashed_header = md5_hash_object.hexdigest()
    return hashed_header

def add_header_to_file(file_path, header):

    with open("imagini/"+file_path, 'rb') as file:
        rest = file.read()

    with open("imagini_noi/"+file_path, 'wb') as file:
        file.write((header[0]+"\n").encode('utf-8'))
        file.write((header[1]+" "+header[2]+"\n").encode('utf-8'))
        file.write((header[3]+"\n").encode('utf-8'))
        rest = decrypt(rest, key)
        file.write(rest)

print(md5_hash("P6 720 960 255"))

for i in range(1,1000):
    for j in range(1,1000):
        header = "P6 " + str(i) + " " + str(j) + " 255"
        header_md5 = md5_hash(header)
        for h in headers_hashed:
            if h==header_md5:
                headers.append(header)

for i in range(4):
    values = headers[i].split()
    size = int(values[1])*int(values[2])
    headers[i]=(headers[i],size)

headers.sort(key = lambda x:x[1])
for i in range(4):
    headers[i]=headers[i][0]
print(headers)


file_info_list = [(f, os.path.getsize(os.path.join("imagini", f))) for f in files]
file_info_list.sort(key= lambda x:x[1])
print(files)
print(file_info_list)
for i in range(1,5):
    nume_fisier = file_info_list[i][0]
    cale_fisier = nume_fisier
    headerlines = headers[i-1].split()
    add_header_to_file(cale_fisier,headerlines)
files.sort()
print(files)
for f in files[1:]:
    img = Image.open("imagini_noi/"+f)
    img.show()
    time.sleep(2)