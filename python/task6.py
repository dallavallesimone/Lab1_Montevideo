from feistel_encryptor import *
import numpy as np

def array_bin (n, length):
    a=np.zeros(32)
    i=length-1
    #print("n:\n")
    #print(n)
    while (n!=0):
        if (n%2 == 1):
            a[i]=1
        else:
            a[i]=0
        n=int(n/2)
        i=i-1
    #print("\na:\n")
    #print(a)
    return a

A = np.zeros((32,32), dtype=int)
B = np.zeros((32,32), dtype=int)
A_cols= np.zeros(32)
B_cols= np.zeros(32)
#A[32][32]
matsize = 32
ej = 0x80000000

for i in range(0, matsize):
    A_cols[i] = encryptTask5(0x0000, 32, ej, 32, 5)
    B_cols[i] = encryptTask5(ej, 32, 0x0000, 32, 5)
    #print("ej: " + str(hex(ej)) + "\n")
    ej = ej>>1


for i in range(0, matsize):
    a=array_bin(int(A_cols[i]), 32)
    b=array_bin(int(B_cols[i]), 32)
    #print("\na: ")
    #print(a)
    #print("\nb: ")
    #print(b)
    for j in range(0, matsize):
        A[j][i]=int(a[j])
        B[j][i]=int(b[j])

"""print("\n---A---\n")
print(A)
print("\n---B---\n")
print(B)"""

det_A = np.linalg.det(A)
A_inv = np.linalg.inv(A) 
Ai = np.rint(A_inv * det_A) % 2


with open(r"C:\Users\massi\Downloads\Lab1_Montevideo_2\KPApairsMontevideo_linear.hex", 'r') as f:
    lines = f.read().split('\n')
# Get x and y values from each line and append to self.data
spec = '{fill}{align}{width}{type}'.format(fill='0', align='>', width=32, type='b')
for line in lines:
    sample = line.split('\t')
    plaintext = str(format(int(sample[0], 16),spec))
    ciphertext = str(format(int(sample[1], 16),spec))

    plaintext = [plaintext[i:i+1] for i in range(0, len(plaintext), 1)]
    plaintext = [int(item) for item in plaintext]
    plaintext = np.array(plaintext)

    ciphertext = [ciphertext[i:i+1] for i in range(0, len(ciphertext), 1)]
    ciphertext = [int(item) for item in ciphertext]
    ciphertext = np.array(ciphertext)

k = np.dot(Ai, ciphertext^np.dot(B, plaintext)) % 2
key = 0x00000000
for i in range(0, 32):
    key = key ^ (int(k[i]) << (32 - i))
     
print("k:", hex(key))

#Check plaintext 6766C94F	76BC0A0D
x=encryptTask5( 0x1ee97f91e, 32, 0x6766C94F, 32, 5)
print("\nx computed: " + str(hex(x))+ "\n")
print("x given: 0x76BC0A0D\n")


