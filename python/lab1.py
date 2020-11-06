from feistel_encryptor import *

number_of_rounds = 13
u = 0x0000
x = 0x6a9b
key = 0x369c

print("ORIGINAL PLAINTEXT: "+str(hex(u)))
print("CYPHERTEXT: "+str(hex(x)))
print("KEY: "+str(hex(key)))
print("CYPHETEXT ENCRYPTED: "+str(hex(encryptTask7(key, 16, u, 16, number_of_rounds))))
print("PLAINTEXT DECRYPTED: "+str(hex(decryptTask7(key, 16, x, 16, number_of_rounds))))