import sys
from BitVector import *

class AES:
    # Class constructor - when creating an AES object, the
    # class's constructor is executed and instance variables
    # are initialized
    def __init__(self, keyfile: str) -> None:

    # encrypt - method performs AES encryption on the plaintext 
    #                            and writes the ciphertext to 
    #                           disk
    # Inputs: plaintext (str) - filename containing plaintext
    #         ciphertext (str) - filename containing ciphertext
    # Return: void

        self.BLOCKSIZE = 128
        self.AES_modulus = BitVector(bitstring='100011011')
        self.subBytesTable = []
        self.invSubBytesTable = []
        
        with open(keyfile, 'r') as file:
            self.key_str = file.read().strip()
            self.key_bv = BitVector(textstring = self.key_str)

        self.genTables()
        self.key_schedule = self.gen_key_schedule_256()

        self.mix_columns_matrix = [[BitVector(intVal = 2), BitVector(intVal = 3), BitVector(intVal = 1), BitVector(intVal = 1)],
                                   [BitVector(intVal = 1), BitVector(intVal = 2), BitVector(intVal = 3), BitVector(intVal = 1)],
                                   [BitVector(intVal = 1), BitVector(intVal = 1), BitVector(intVal = 2), BitVector(intVal = 3)],
                                   [BitVector(intVal = 3), BitVector(intVal = 1), BitVector(intVal = 1), BitVector(intVal = 2)]]

        self.inv_mix_columns_matrix = [[BitVector(intVal = 14), BitVector(intVal = 11), BitVector(intVal = 13), BitVector(intVal = 9)], 
                                       [BitVector(intVal = 9), BitVector(intVal = 14), BitVector(intVal = 11), BitVector(intVal = 13)],
                                       [BitVector(intVal = 13), BitVector(intVal = 9), BitVector(intVal = 14), BitVector(intVal = 11)],
                                       [BitVector(intVal = 11), BitVector(intVal = 13), BitVector(intVal = 9), BitVector(intVal = 14)]]

    def genTables(self):
        c = BitVector(bitstring='01100011')
        d = BitVector(bitstring='00000101')
        for i in range(0, 256):
            # For the encryption SBox
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            # For bit scrambling for the encryption SBox entries:
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            self.subBytesTable.append(int(a))
            # For the decryption Sbox:
            b = BitVector(intVal = i, size=8)
            # For bit scrambling for the decryption SBox entries:
            b1,b2,b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
            check = b.gf_MI(self.AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            self.invSubBytesTable.append(int(b))

    def gee(self, keyword, round_constant, byte_sub_table):
        '''
        This is the g() function you see in Figure 4 of Lecture 8.
        '''
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
        return newword, round_constant

    def gen_key_schedule_256(self):
        byte_sub_table = self.subBytesTable
        #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
        #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
        #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
        #  schedule. We will store all 60 keywords in the following list:
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(8):
            key_words[i] = self.key_bv[i*32 : i*32 + 32]
        for i in range(8,60):
            if i%8 == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant, byte_sub_table)
                key_words[i] = key_words[i-8] ^ kwd
            elif (i - (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i - (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = 
                                    byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8] 
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words

    def encrypt(self, plaintext:str, ciphertext:str) -> None:

    # decrypt - method performs AES decryption on the ciphertext
    #                           and writes the recovered plaintext 
    #                           to disk
    # Inputs: ciphertext (str) - filename containing ciphertext
    #         decrypted (str) - filename containing recovered 
    #                           plaintext
    # Return: void

        with open(plaintext, 'r') as file:
            plaintext_data = file.read()


        with open("encrypted.txt", 'w') as file:
            file.write("")
    def decrypt(self, ciphertext:str, decrypted:str) -> None:

if __name__ == "__main__":
    cipher = AES(keyfile = sys.argv[3])

    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2],ciphertext=sys.argv[4])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], decrypted=sys.argv[4])
    else:
        sys.exit("Incorrect Command-Line Syntax")