#include <stdio.h>
unsigned int subkey_generation(unsigned int k, int round_number, int bit_position);

int main() {
	int number_of_rounds = 17;

	//The plaintext
	unsigned int u = 0x80000000;
	//The key
	unsigned int k = 0x80000000;
	//The cyphertext 
	unsigned int x = 0x80000000;

	for (int i = 1; i <= 17; i++) {

		//Variable used to keep the changes caused by (yi xor ki)
		unsigned int new_word = 0x00000000;
		for (int j = 1; j <= 16; j++) {

			//Shift of 16 in order to start from the second half of the plaintext
			int shift = 16 - j;

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
			tmp = tmp << shift;
			new_word = new_word | tmp;
		}

		//Shift of 16 in order to allow us to sum with the first half of
		//the plaintext
		new_word = new_word << 16;

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
		//printf("new x: %x\n\n\n\n\n", x);
	}
	printf("CYPHERTEXT: %x\n", x);
	return 0;
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