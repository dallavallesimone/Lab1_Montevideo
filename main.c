#include <stdio.h>
unsigned int subkey_generation(unsigned int k, int round_number, int bit_position);

unsigned int encrypt(unsigned int k, unsigned int u);
unsigned int decrypt(unsigned int k, unsigned int x);

int main() {
	int number_of_rounds = 17;

	//The plaintext
	unsigned int u = 0xcacca123;
	//The key
	unsigned int k = 0x12345678;
	
	printf("Original PLAINTEXT: %x\n", u);

	// task1 - implement encryption
	unsigned int x = encrypt(k, u);
	printf("CYPHERTEXT: %x\n", x);

	// task2 - implement decryption
	unsigned int u_decrypt = decrypt(k, x);
	printf("Computed PLAINTEXT: %x\n", u_decrypt);

	// task3 - identify the linear relationship
	// compute A and B matrixes and store them in columns
	unsigned int A_matrix_cols[32];
	unsigned int B_matrix_cols[32];
	unsigned int eigenvalue = 0x80000000;
	for (int i = 0; i < 32; i++)
	{
		A_matrix_cols[i] = encrypt(eigenvalue, 0); // i-th colomn
		B_matrix_cols[i] = encrypt(0, eigenvalue);
		eigenvalue = eigenvalue >> 1;
	}
	// compute A*k and B*u
	// using the following property:
	// (col1 ... col32)* (v1 ... v32)^T = col1 * v1 + ... + col32 * v32
	// where matrix A = (col1 ... col32)
	// and column vector v = (v1 ... v32)^TT
	eigenvalue = 0x80000000;
	unsigned int first_prod = 0; // A*k
	unsigned int second_prod = 0; // B*u
	for (int i = 0; i < 32; i++)
	{
		if ((k & eigenvalue) == 0) { // k[i] = 0 (i-th bit)
			A_matrix_cols[i] = 0;
		}
		if ((u & eigenvalue) == 0) { // u[i] = 0 (i-th bit)
			B_matrix_cols[i] = 0;
		}
		eigenvalue = eigenvalue >> 1;
		first_prod ^= A_matrix_cols[i];
		second_prod ^= B_matrix_cols[i];
	}
	unsigned int result = first_prod ^ second_prod; 
	printf("Ciphertext computed as linear combination of k and u: %x\n", result);

	return 0;
}

unsigned int encrypt(unsigned int k, unsigned int u) {
	// assign plaintext to cyphertext 
	unsigned int x = u;
	for (int i = 1; i <= 17; i++) {

		//Variable used to keep the changes caused by (yi xor ki)
		unsigned int new_word = 0x00000000;
		for (int j = 1; j <= 16; j++) {

			//Shift of 16 in order to start from the second half of the plaintext
			//int shift = 16 - j;
			int shift = 32 - j;

			//Do a right shift in order to put the bit we want to
			//the least significant bit
			unsigned int tmp = x >> shift;
			//printf("x after shift: %x\n", tmp);

			//Keep only the least significant bit
			tmp = tmp & 0x00000001;
			//printf("x after applying the mask: %x\n", tmp);

			//Change the bit to choose from the key following the pdf instructions
			int right_j = 0;
			if (j <= 8) {
				right_j = 4 * j - 3;
			}
			else {
				right_j = 4 * j - 32;
			}

			//Do the xor operation and do a left shift in order to 
			//update new_word
			//printf("subkey: %x\n   tmp: %x\n", subkey_generation(k, i, right_j), tmp);
			tmp = tmp ^ subkey_generation(k, i, right_j);
			//printf("tmp after xor: %x\n\n", tmp);
			tmp = tmp << (shift - 16);
			new_word = new_word | tmp;
		}

		//Xor operation to the first half of the plaintext
		x = x ^ new_word;
		//printf("shifted: %x\n", new_word);
		//printf("new x: %x\n", x);

		//Swap the 2 halves of the text
		if (i != 17) {
			unsigned int mask1 = 0xffff0000;
			unsigned int mask2 = 0xffff;
			unsigned int x_left = (x & mask1) >> 16;
			unsigned int x_right = (x & mask2) << 16;
			//printf("x: %x\n", x);
			//printf("left: %x\n", x_left);
			//printf("right: %x\n", x_right);
			x = x_left | x_right;
			//printf("new x: %x\n", x);
		}
	}
	return x;
}

unsigned int decrypt(unsigned int k, unsigned int x) {
	// assign cyphertext to plaintext 
	unsigned int u = x;
	for (int i = 1; i <= 17; i++) {

		//Variable used to keep the changes caused by (yi xor ki)
		unsigned int new_word = 0x00000000;
		for (int j = 1; j <= 16; j++) {

			//Shift of 16 in order to start from the second half of the plaintext
			//int shift = 16 - j;
			int shift = 32 - j;

			//Do a right shift in order to put the bit we want to
			//the least significant bit
			unsigned int tmp = u >> shift;
			//printf("x after shift: %x\n", tmp);

			//Keep only the least significant bit
			tmp = tmp & 0x00000001;
			//printf("x after applying the mask: %x\n", tmp);

			//Change the bit to choose from the key following the pdf instructions
			int right_j = 0;
			if (j <= 8) {
				right_j = 4 * j - 3;
			}
			else {
				right_j = 4 * j - 32;
			}

			//Do the xor operation and do a left shift in order to 
			//update new_word
			//printf("subkey: %x\n   tmp: %x\n", subkey_generation(k, i, right_j), tmp);
			tmp = tmp ^ subkey_generation(k, 18-i, right_j);
			//printf("tmp after xor: %x\n\n", tmp);
			tmp = tmp << (shift - 16);
			new_word = new_word | tmp;
		}

		//Xor operation to the first half of the plaintext
		u = u ^ new_word;
		//printf("shifted: %x\n", new_word);
		//printf("new x: %x\n", x);

		//Swap the 2 halves of the text
		if (i != 17) {
			unsigned int mask1 = 0xffff0000;
			unsigned int mask2 = 0xffff;
			unsigned int u_left = (u & mask1) >> 16;
			unsigned int u_right = (u & mask2) << 16;
			//printf("x: %x\n", x);
			//printf("left: %x\n", x_left);
			//printf("right: %x\n", x_right);
			u = u_left | u_right;
			//printf("new x: %x\n", x);
		}
	}
	return u;
}


unsigned int subkey_generation(unsigned int k, int round_number, int bit_position) {

	//bit_selector is a mask composed by [1, 0, 0, 0, ...,0] (dimensions of 
	//this number in bit is 32)
	unsigned int bit_selector = 0x80000000;

	//Here i compute the position of the bit in the original key (computing by
	//following the pdf)
	int bit_position_old_key = ((5 * round_number + bit_position - 1) % 32) + 1;

	//Here I do a right shift in order to move the 1 to the position of the bit
	//we want to extract from the key
	if (bit_position_old_key != 1) {
		bit_selector = bit_selector >> (bit_position_old_key - 1);
	}

	//Through bitwise AND between k (the key) and bit_selector(the mask)
	//I obtain a unsigned int with the rightmost bit that is the same of 
	//the one of the key in the position bit_position_old_key
	unsigned int bit_value = k & bit_selector;

	//I do the shift in order to give back to the function only 1 bit
	return bit_value >> 32 - bit_position_old_key;
}