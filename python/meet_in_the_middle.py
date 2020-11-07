from random import *
from feistel_encryptor import *

def meet_in_the_middle(file_name):

    #Open the file with the keys
    key_file = open(file_name, "r")
    lines = key_file.readlines()

    #List to save each key-pairs found
    key_found = []

    for line in lines:
        #Initializing the lists
        k1_guesses = []
        k2_guesses = []
        tuples_1 = []
        tuples_2 = []

        #Generating rundom number
        for i in range(1, 1001):
            k1_guesses.append(randrange(1, 65537))
            k2_guesses.append(randrange(1, 65537))
    
        #Encrypting all the plaintext and saves them with their keys
        for i in k1_guesses:
            tuples_1.append((encryptTask7(i, 16, int(line.split()[0], 16), 16, 13), i))
        tuples_1.sort()
        #f = open("tuples_1.txt", "w")
        #f.write(str(tuples_1))
        #f.close()

        #Decrypting all the ciphertext and saves them with their keys
        for i in k2_guesses:
            tuples_2.append((decryptTask7(i, 16, int(line.split()[1], 16), 16, 13), i))
        tuples_2.sort()
        #f = open("tuples_2.txt", "w")
        #f.write(str(tuples_2))
        #f.close()

        #Looks for the equals text encrypted and decrypted
        #and save the key pairs
        for i in tuples_1:
            for j in tuples_2:
                if(i[0] == j[0]):
                    key_found.append((i[1], j[1]))
        break

    keys=[]
    if(len(key_found)!=0):
        keys = list(set(key_found))
        keys.sort()

    return keys