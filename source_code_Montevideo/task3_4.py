from feistel_encryptor import *
import numpy as np

def binary_matrices():
    """ Compute the A matrix and the B matrix from the
    relation described in the pdf
    """

    #Prepare the matrices and the arrays to store
    #the columns of the matrices
    A_matrix = np.zeros([32, 32])
    B_matrix = np.zeros([32, 32])
    a_cols = []
    b_cols = []

    #Value used to compute the columns
    eigenvalue = 0x80000000

    for i in range(0, 32):
        a_cols.append(encryptTask1(eigenvalue, 32, 0, 32, 17))
        b_cols.append(encryptTask1(0, 32, eigenvalue, 32, 17))
        eigenvalue = eigenvalue >> 1

    #Reset the eigenvalue and compile the matrices
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

    #Saves the matrices
    np.savetxt("A_mat.txt", np.asmatrix(A_matrix), fmt="%d")
    np.savetxt("B_mat.txt", np.asmatrix(B_matrix), fmt="%d")

    return [A_matrix, B_matrix]


def linearKPA(A_matrix, B_matrix, file_name):
    """Given the binary matrices A and B and some couples
    of plaintext/ciphertext (all encoded with the same key)
    it computes the key used in encryptorTask1 of fesitel_encryptors.py

    Keyword arguments:
    A_matrix -- the matrix A
    B_matrix -- the matrix B
    file_name -- the file where are saved the pairs of plaintext/ciphertext, 
        one for each line
    """

    #Open the file and read all the lines
    with open("dataset/KPApairsMontevideo_linear.hex", 'r') as f:
        lines = f.readlines()

    #Array that stores all the keys
    keys = []

    #Compute the binary inverse of A_matrix
    A_inverse = np.linalg.inv(A_matrix)
    A_det = np.linalg.det(A_matrix)
    A_binary_inverse = np.rint(A_inverse * A_det) % 2

    #Formats the matrix in order to have no errors
    B_matrix = B_matrix.astype(int)
    A_binary_inverse = A_binary_inverse.astype(int)
    
    #For each line it compute the key by using the relation in
    #the pdf and save them into an array
    spec = '{fill}{align}{width}{type}'.format(fill='0', align='>', width=32, type='b')
    for line in lines:
        sample = line.split('\t')
        plaintext = str(format(int(sample[0], 16), spec))
        ciphertext = str(format(int(sample[1], 16), spec))

        plaintext = [plaintext[i:i+1] for i in range(0, len(plaintext), 1)];
        plaintext = [int(item) for item in plaintext]
        plaintext = np.array(plaintext)
  
        ciphertext = [ciphertext[i:i+1] for i in range(0, len(ciphertext), 1)];
        ciphertext = [int(item) for item in ciphertext]
        ciphertext = np.array(ciphertext)

        key = np.dot(A_binary_inverse, ciphertext^np.dot(B_matrix, plaintext)) % 2
        
        key_hex = 0x00000000
        for i in range(0, 32):
            key_hex = key_hex ^ (int(key[i]) << (31 - i))

        #Add the key to the array
        keys.append(key_hex)
    
    #Delete the duplicates from the list and if there
    #is more than 1 raise an error
    keys_no_duplicates = list(set(keys))
    if(len(keys_no_duplicates)!=1):
        raise Exception
    
    return keys_no_duplicates[0]