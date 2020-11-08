from random import *
from feistel_encryptor import *

def meet_in_the_middle(file_name):
    """Return an array with all the pairs of keys found
    using the meet-in-the-middle attack

    Keyword Arguments:
    file_name -- The name of the file to read where there are the
        plaintext/ciphertext couples
    """

    #Open the file with the keys
    key_file = open(file_name, "r")
    lines = key_file.readlines()
    key_file.close()

    #List to save each key-pairs found
    keys = []

    #Initializing the lists
    k1_guesses = []
    k2_guesses = []
    tuples_1 = []
    tuples_2 = []
    
    #Generating rundom number
    for i in range(1, 1000):
        k1_guesses.append(randrange(1, 65537))
        k2_guesses.append(randrange(1, 65537))
    
    #To find the key we try only on the first pair of plaintext/ciphertext
    #and then we look if the found keys are working either on the other pairs

    #Encrypting all the plaintext and saves them with their keys
    for i in k1_guesses:
        tuples_1.append((encryptTask7(i, 16, int(lines[0].split()[0], 16), 16, 13), i))
    tuples_1.sort()

    #Decrypting all the ciphertext and saves them with their keys
    for i in k2_guesses:
        tuples_2.append((decryptTask7(i, 16, int(lines[0].split()[1], 16), 16, 13), i))
    tuples_2.sort()

    #Looks for the equals text encrypted and decrypted
    #and save the key pairs
    for i in tuples_1:
        for j in tuples_2:
            #If the xi and xii
            if(i[0] == j[0]):
                flag = True
                for pair in range(1, 5):
                    first_cipher = encryptTask7(i[1], 16, int(lines[pair].split()[0], 16), 16, 13)
                    second_cipher = encryptTask7(j[1], 16, first_cipher, 16, 13)
                    #Check if the encrypted plaintext and the ciphertext from the file are equal
                    if(second_cipher != int(lines[pair].split()[1], 16)):
                        flag = False
                        break
                if(flag == True):
                    keys.append((i[1], j[1]))

    return keys 