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

print("\n---A---\n")
print(A)
print("\n---B---\n")
print(B)
