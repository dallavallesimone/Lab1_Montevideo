from feistel_encryptor import *
from meet_in_the_middle import *
from task3_4 import *
import numpy as np

print("---- Montevideo Group ----")
print("---TASK 1 and 2---")
u = 0x80000000
key = 0x80000000
x = 0xD80B1A63
number_of_rounds = 17

print("ORIGINAL PLAINTEXT: "+str(hex(u)))
print("ORIGINAL CIPHERTEXT: "+str(hex(x)))
print("ORIGINAL KEY: "+str(hex(key)))
print("CYPHERTEXT ENCRYPTED: "+str(hex(encryptTask1(key, 32, u, 32, number_of_rounds))))
print("PLAINTEXT DECRYPTED: "+str(hex(decryptTask1(key, 32, x, 32, number_of_rounds)))+"\n\n")

print("---TASK 3---")
matrices = binary_matrices()
print("The matrices are:\nA:")
print(matrices[0])
print("B:")
print(matrices[1])
print("They can be found on the file A_matrix.txt and B_matrix.txt\n\n")

print("---TASK 4---")
key_task4 = linearKPA(matrices[0], matrices[1], "dataset/KPApairsMontevideo_linear.hex")
print("KEY FOUND: "+ str(hex(key_task4))+"\n\n")

print("---TASK 5---")
u = 0x12345678
key = 0x87654321
x = 0x2E823D53
number_of_rounds = 5

print("ORIGINAL PLAINTEXT: "+str(hex(u)))
print("ORIGINAL CIPHERTEXT: "+str(hex(x)))
print("ORIGINAL KEY: "+str(hex(key)))
print("CYPHERTEXT ENCRYPTED: "+str(hex(encryptTask5(key, 32, u, 32, number_of_rounds))))
print("PLAINTEXT DECRYPTED: "+str(hex(decryptTask5(key, 32, x, 32, number_of_rounds)))+"\n\n")


print("---TASK 7---")
u = 0x0000
key = 0x369C
x = 0x6A9B
number_of_rounds = 13

print("ORIGINAL PLAINTEXT: "+str(hex(u)))
print("ORIGINAL CIPHERTEXT: "+str(hex(x)))
print("ORIGINAL KEY: "+str(hex(key)))
print("CYPHERTEXT ENCRYPTED: "+str(hex(encryptTask7(key, 16, u, 16, number_of_rounds))))
print("PLAINTEXT DECRYPTED: "+str(hex(decryptTask7(key, 16, x, 16, number_of_rounds)))+"\n\n")


print("---TASK 8---")
keys_found = meet_in_the_middle("dataset/KPApairsMontevideo_non_linear.hex")
print("KEYS FOUND: "+str(keys_found))