from feistel_encryptor import *
import numpy as np

number_of_rounds = 13
u = 0x0000
x = 0x6a9b
key = 0x369c

print("ORIGINAL PLAINTEXT: "+str(hex(u)))
print("CYPHERTEXT: "+str(hex(x)))
print("KEY: "+str(hex(key)))
print("CYPHETEXT ENCRYPTED: "+str(hex(encryptTask7(key, 16, u, 16, number_of_rounds))))
print("PLAINTEXT DECRYPTED: "+str(hex(decryptTask7(key, 16, x, 16, number_of_rounds))))


#Ugly implementation of the code becuse I can't read matrix.csv
A_matrix = np.zeros([32, 32])
B_matrix = np.zeros([32, 32])
a_cols = []
b_cols = []

eigenvalue = 0x80000000

for i in range(0, 32):
    a_cols.append(encryptTask1(eigenvalue, 32, 0, 32, 17))
    b_cols.append(encryptTask1(0, 32, eigenvalue, 32, 17))
    eigenvalue = eigenvalue >> 1

eigenvalue = 0x80000000
for i in range(0,32):
    for j in range(0,32):
        if(eigenvalue & a_cols[j] == 0):
            A_matrix[i][j] = 0
        else:
            A_matrix[i][j] = 1
        if(eigenvalue & b_cols[j] == 0):
            B_matrix[i][j] = 0
        else:
            B_matrix[i][j] = 1
    eigenvalue = eigenvalue >> 1

A_inverse = np.linalg.inv(A_matrix)
A_det = np.linalg.det(A_matrix)
A_binary_inverse = np.rint(A_inverse * A_det) % 2

B_matrix = B_matrix.astype(int)

with open("KPApairsMontevideo_linear.hex", 'r') as f:
  lines = f.read().split('\n')
# Get x and y values from each line and append to self.data
spec = '{fill}{align}{width}{type}'.format(fill='0', align='>', width=32, type='b')
for line in lines:
  sample = line.split('\t')
  plaintext = str(format(int(sample[0], 16),spec))
  ciphertext = str(format(int(sample[1], 16),spec))

  plaintext = [plaintext[i:i+1] for i in range(0, len(plaintext), 1)];
  plaintext = [int(item) for item in plaintext]
  plaintext = np.array(plaintext)
  
  ciphertext = [ciphertext[i:i+1] for i in range(0, len(ciphertext), 1)];
  ciphertext = [int(item) for item in ciphertext]
  ciphertext = np.array(ciphertext)

  k = np.dot(A_binary_inverse, ciphertext^np.dot(B_matrix, plaintext)) % 2

  key = 0x00000000
  for i in range(0, 32):
      key = key ^ (int(k[i]) << (32 - i))

  print("k:\n", hex(key))