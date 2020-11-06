def subkey_generation(k, round_number, bit_position, key_length):
    """Return the value of the key at the position bit_position
    using the specification given in the pdf

    Keyword arguments:
    k -- the key used to compute the new key
    round_number -- the number of the round at which it's computing the key
    bit_position -- the position of the bit we want to know
    ley_length -- the length of the key
    """
    
    #bit_selector is a mask composed by [1, 0, 0, 0, ...,0] (dimensions of
    #this number in bit is 32)
    bit_selector = 0x1

    #Here i compute the position of the bit in the original key (computing by
    #following the pdf)
    bit_position_old_key = ((5 * round_number + bit_position - 1) % key_length) + 1

    #Here I do a right shift in order to move the 1 to the position of the bit
    #we want to extract from the key
    bit_selector = bit_selector << (key_length - bit_position_old_key)

    #Through bitwise AND between k (the key) and bit_selector(the mask)
    #I obtain a unsigned int with the rightmost bit that is the same of 
    #the one of the key in the position bit_position_old_key
    bit_value = k & bit_selector

    #I do the shift in order to give back to the function only 1 bit
    return bit_value >> (key_length-bit_position_old_key)



def bit_extractor(y, y_length, bit_position):
    """ Extract a specified bit at bit_position from
    the number y. If bit_position is greater than y_length
    raise an error

    Keyword arguments:
    y -- the number from which the bit is exctrated
    y_length -- the length of y
    bit_position -- the position of the bit inside the number
    """
    if(bit_position > y_length):
        raise ValueError

    mask = 0x1
    mask = mask << y_length - bit_position
    tmp = y & mask
    return tmp >> y_length - bit_position




def encryptTask1(k, key_legth, u, u_length, number_rounds):
    """Encrypt the plaintext u using the feistel cipher with
    key k and number_round as rounds. The round function is 
    equal to the one specified in the pdf

    Keyword arguments:
    k -- the key used to encrypt
    k_length -- the length of the key
    u -- the plaintext to encrypt
    u_length -- the length of the plaintext
    number_round -- the number of round used to encrypt the plaintext
    """
    #Assign plaintext to cyphertext 
    x = u

    for i in range(1, (number_rounds + 1)):
        #Variable used to keep the changes caused by (yi xor ki)
        new_word = 0x00000000
        
        for j in range(1, int(u_length/2 + 1)):
            #Shift of 32 in order to start from the first half of the plaintext
            shift = u_length - j

            #Do a right shift in order to put the bit we want to
            #the least significant bit
            tmp = x >> shift

            #Keep only the least significant bit
            tmp = tmp & 0x1

            #Change the bit to choose from the key following the pdf instructions
            right_j = 0
            if(j<=8):
                right_j = 4 * j - 3
            else:
                right_j = 4 * j - int(u_length)
            
            #Do the xor operation and do a left shift in order to
            #update new_word
            tmp = tmp ^ subkey_generation(k, i, right_j, key_legth)
            tmp = tmp << (shift - (int)(u_length/2))
            new_word = new_word | tmp

        #Xor operation to the first half of the plaintext
        x = x ^ new_word

        #Swap the 2 halves of the text
        if(i != number_rounds):
            mask1 = 0xffff0000
            mask2 = 0xffff
            x_left = (x & mask1) >> int(u_length/2)
            x_right = (x & mask2) << int(u_length/2)
            x= x_left | x_right

    return x



def decryptTask1(k, k_length, x, x_length, number_rounds):
    """Decrypt the ciphertext u using the feistel cipher with
    key k and number_round as rounds. The round function is 
    equal to the one specified in the pdf

    Keyword arguments:
    k -- the key used to decrypt
    k_length -- the length of the key
    x -- the ciphertext to decrypt
    x_length -- the length of the ciphertext
    number_round -- the number of round used to decrypt the ciphertext
    """
    #Assign cyphertext to plaintext 
    u = x

    for i in range(1, (number_rounds + 1)):
        #Variable used to keep the changes caused by (yi xor ki)
        new_word = 0x00000000
        
        for j in range(1, int(x_length/2+1)):
            #Shift of x_length in order to start from the first half of the plaintext
            shift = x_length - j

            #Do a right shift in order to put the bit we want to
            #the least significant bit
            tmp = u >> shift

            #Keep only the least significant bit
            tmp = tmp & 0x00000001

            #Change the bit to choose from the key following the pdf instructions
            right_j = 0
            if(j<=8):
                right_j = 4 * j - 3
            else:
                right_j = 4 * j - int(x_length)
            
            #Do the xor operation and do a left shift in order to
            #update new_word
            tmp = tmp ^ subkey_generation(k, (number_rounds + 1 - i), right_j, k_length)
            tmp = tmp << (shift - int(x_length/2))
            new_word = new_word | tmp

        #Xor operation to the first half of the plaintext
        u = u ^ new_word

        #Swap the 2 halves of the text
        if(i != number_rounds):
            mask1 = 0xffff0000
            mask2 = 0xffff
            u_left = (u & mask1) >> int(x_length/2)
            u_right = (u & mask2) << int(x_length/2)
            u = u_left | u_right

    return u



def encryptTask5(k, k_length, u, u_length, number_rounds):
    """Encrypt the plaintext u using the feistel cipher with
    key k and number_round as rounds. The round function is 
    equal to the one specified in the pdf

    Keyword arguments:
    k -- the key used to encrypt
    k_length -- the length of the key
    u -- the plaintext to encrypt
    u_length -- the length of the plaintext
    number_round -- the number of round used to encrypt the plaintext
    """
    #Assign plaintext to chiphertext
    x = u

    for i in range(1, (number_rounds +1)):
        #Variable used to keep the changes caused by (yi xor ki)
        new_word = 0x0

        for j in range(1, int(u_length/2+1)):
            #Shift of 32 in order to start from the first half of the plaintext
            shift = u_length - j

            #Do a right shift in order to put the bit we want to
            #the least significant bit
            tmp = x >> shift

            #Keep only the least significant bit
            tmp = tmp & 0x1

            #Compute the value that will be used to do the xor with x
            xor_value = 0x00000000
            if(j<=8):
                xor_value = subkey_generation(k, i, 4*j-3, k_length) & (bit_extractor(x, u_length, 2*j-1) 
                | subkey_generation(k, i, 2*j-1, k_length) | subkey_generation(k, i, 2*j, k_length) 
                | subkey_generation(k, i, 4*j-2, k_length))
            else:
                xor_value = subkey_generation(k, i, 4*j-u_length, k_length) & (subkey_generation(k, i, 4*j-u_length-1, k_length) 
                | subkey_generation(k, i, 2*j-1, k_length) | subkey_generation(k, i,2*j, k_length) 
                | bit_extractor(x, u_length, 2*j-int(u_length/2)))

            #Do the xor operation and do a left shift in order to
            #update new_word
            tmp = tmp ^ xor_value           
            tmp = tmp << (shift-int(u_length/2))
            new_word = new_word | tmp

        #Xor operation to the first half of the plaintext
        x = x ^ new_word

        #Swap the 2 halves of the text
        if(i != number_rounds):
            mask1 = 0xffff0000
            mask2 = 0xffff
            x_left = (x & mask1) >> int(u_length/2)
            x_right = (x & mask2) << int(u_length/2)
            x= x_left | x_right

    return x



def decryptTask5(k, k_length, x, x_length, number_rounds):
    """Decrypt the ciphertext u using the feistel cipher with
    key k and number_round as rounds. The round function is 
    equal to the one specified in the pdf

    Keyword arguments:
    k -- the key used to decrypt
    k_length -- the length of the key
    x -- the ciphertext to decrypt
    x_length -- the length of the ciphertext
    number_round -- the number of round used to decrypt the ciphertext
    """
    #Assign cyphertext to plaintext
    u = x

    for i in range(1, (number_rounds +1)):
        #Variable used to keep the changes caused by (yi xor ki)
        new_word = 0x00000000

        for j in range(1, int(x_length/2+1)):
             #Shift of 32 in order to start from the first half of the chypertext
            shift = x_length - j

            #Do a right shift in order to put the bit we want to
            #the least significant bit
            tmp = u >> shift
            tmp = tmp & 0x1

            #Keep only the least significant bit
            xor_value = 0x0

            #Compute the value that will be used to do the xor with u
            if(j<=8):
                xor_value = subkey_generation(k, (number_rounds + 1 - i), 4*j-3, k_length) & (bit_extractor(u, x_length, 2*j-1) 
                | subkey_generation(k, (number_rounds + 1 - i), 2*j-1, k_length) 
                | subkey_generation(k, (number_rounds + 1 - i), 2*j, k_length) 
                | subkey_generation(k, (number_rounds + 1 - i), 4*j-2, k_length))
            else:
                xor_value = subkey_generation(k, (number_rounds + 1 - i), 4*j-x_length, k_length) & (subkey_generation(k, (number_rounds + 1 - i), 4*j-x_length-1, k_length) 
                | subkey_generation(k, (number_rounds + 1 - i), 2*j-1, k_length) 
                | subkey_generation(k, (number_rounds + 1 - i),2*j, k_length) 
                | bit_extractor(u, x_length, 2*j-int(x_length/2)))

            #Do the xor operation and do a left shift in order to
            #update new_word
            tmp = tmp ^ xor_value
            tmp = tmp << (shift - int(x_length/2))
            new_word = new_word | tmp

        #Xor operation to the first half of the chypertext
        u = u ^ new_word

        #Swap the 2 halves of the text
        if(i != number_rounds):
            mask1 = 0xffff0000
            mask2 = 0xffff
            u_left = (u & mask1) >> int(x_length/2)
            u_right = (u & mask2) << int(x_length/2)
            u = u_left | u_right

    return u


def encryptTask7(k, k_length, u, u_length, number_rounds):
    """Encrypt the plaintext u using the feistel cipher with
    key k and number_round as rounds. The round function is 
    equal to the one specified in the pdf

    Keyword arguments:
    k -- the key used to encrypt
    k_length -- the length of the key
    u -- the plaintext to encrypt
    u_length -- the length of the plaintext
    number_round -- the number of round used to encrypt the plaintext
    """
    #Assign plaintext to cyphertext 
    x = u

    for i in range(1, (number_rounds + 1)):
        #Variable used to keep the changes caused by (yi xor ki)
        new_word = 0x0000
        
        for j in range(1, int(u_length / 2 + 1)):
            
            #Implementation of the and, or operations described in the pdf
            tmp = 0
            first_part = bit_extractor(x, u_length, j) & subkey_generation(k, i, 2*j-1, k_length)
            if(j<=4):
                second_part = bit_extractor(x, u_length, 2*j-1) & subkey_generation(k, i, 2*j, k_length)
                tmp = first_part | second_part | subkey_generation(k, i, 4*j, k_length)
            else:
                second_part = subkey_generation(k, i, 4*j-u_length-1, k_length) & subkey_generation(k, i, 2*j, k_length)
                tmp = first_part | second_part | bit_extractor(x, u_length, 2*j-int(u_length / 2))
            
            #Do the xor operation and do a left shift in order to
            #update new_word
            tmp = tmp << (int(u_length / 2) - j)
            new_word = new_word | tmp

        #Xor operation to the first half of the plaintext
        x = x ^ new_word

        #Swap the 2 halves of the text
        if(i != number_rounds):
            mask1 = 0xff00
            mask2 = 0xff
            x_left = (x & mask1) >> int(u_length / 2)
            x_right = (x & mask2) << int(u_length / 2)
            x= x_left | x_right

    return x

def decryptTask7(k, k_length, x, x_length, number_rounds):
    """Encrypt the plaintext u using the feistel cipher with
    key k and number_round as rounds. The round function is 
    equal to the one specified in the pdf

    Keyword arguments:
    k -- the key used to decrypt
    k_length -- the length of the key
    x -- the ciphertext to decrypt
    x_length -- the length of the ciphertext
    number_round -- the number of round used to encrypt the plaintext
    """
    #Assign plaintext to cyphertext 
    u = x

    for i in range(1, (number_rounds + 1)):
        #Variable used to keep the changes caused by (yi xor ki)
        new_word = 0x0000
        
        for j in range(1, int(x_length / 2 + 1)):
            
            #Implementation of the and, or operations described in the pdf
            tmp = 0
            first_part = bit_extractor(u, x_length, j) & subkey_generation(k, (number_rounds + 1 - i), 2*j-1, k_length)
            if(j<=4):
                second_part = bit_extractor(u, x_length, 2*j-1) & subkey_generation(k, (number_rounds + 1 - i), 2*j, k_length)
                tmp = first_part | second_part | subkey_generation(k, (number_rounds + 1 - i), 4*j, k_length)
            else:
                second_part = subkey_generation(k, (number_rounds + 1 - i), 4*j-x_length-1, k_length) & subkey_generation(k, (number_rounds + 1 - i), 2*j, k_length)
                tmp = first_part | second_part | bit_extractor(u, x_length, 2*j-int(x_length / 2))
            
            #Do the xor operation and do a left shift in order to
            #update new_word
            tmp = tmp << (int(x_length / 2) - j)
            new_word = new_word | tmp

        #Xor operation to the first half of the plaintext
        u = u ^ new_word

        #Swap the 2 halves of the text
        if(i != number_rounds):
            mask1 = 0xff00
            mask2 = 0xff
            u_left = (u & mask1) >> int(x_length / 2)
            u_right = (u & mask2) << int(x_length / 2)
            u = u_left | u_right

    return u
