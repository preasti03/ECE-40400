import sys
from BitVector import *
from PrimeGenerator import *
from solve_pRoot import *

class RSA():
    def __init__(self, e) -> None:
        self.e = e      # Public Key
        self.n = None   # Modulus
        self.d = None   # Private Key
        self.p = None   # Prime 1
        self.q = None   # Prime 2

    def generate_primes(self) -> None:
        # Create an instance of the prime generator class
        prime_gen = PrimeGenerator(bits=128, debug=False)

        # Initialize p and q to 0 to begin loop
        self.p = 0
        self.q = 0

        while True:
            # Ensure p and q satisfy the conditions
            while self.p == self.q or (self.p - 1) % self.e == 0 or (self.q - 1) % self.e == 0:
                self.p = prime_gen.findPrime()
                self.q = prime_gen.findPrime()

                # Ensure the two left most bits are set
                self.p |= (1 << 127)
                self.p |= (1 << 126)  
                self.q |= (1 << 127)
                self.q |= (1 << 126)  
        
            # Check if conditions are met
            if self.p != self.q and self.are_coprime(self.p - 1, self.e) and self.are_coprime(self.q - 1, self.e):
                break


    # Calculate modulus n and private key d
    def calc_n_d(self) -> None:
        self.n = self.p * self.q 
        phi_n = (self.p - 1) * (self.q - 1)
        self.d = self.mod_inv(self.e, phi_n)
        print(f"Calculated n: {self.n}")
        print(f"Calculated d: {self.d}")
        print(f"Totient(n): {phi_n}")
       
    # write primes p and q to files p_file and q_file
    def generate_keys(self, p_file:str, q_file:str) -> None:
        self.generate_primes()
        self.calc_n_d()

        with open(p_file, 'w') as f:
            f.write(str(self.p))
        with open(q_file, 'w') as f:
            f.write(str(self.q))

    # get p and q from files
    def read_keys(self, p_file:str, q_file:str) -> None:
        with open(p_file, 'r') as f:
            self.p = int(f.read().strip())
        with open(q_file, 'r') as f:
            self.q = int(f.read().strip())

        
        self.calc_n_d()

    # check if two numbers are coprime
    def are_coprime(self, a:int, b:int) -> bool:
        while b:
            a, b = b, a % b
        return a == 1

    # calculate modular inverse (for d)
    def mod_inv(self, a: int, m: int) -> int:
        return int(BitVector(intVal=a).multiplicative_inverse(BitVector(intVal=m)))

    # encryption process
    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        # read plaintext from file
        with open(plaintext, 'r') as f:
            message = f.read()
        
        # convert message to a bit vector 
        bv = BitVector(textstring=message)
        
        # pad with zeros to get 128 bit blocks
        if len(bv) % 128 != 0:
            padding_bits = 128 - (len(bv) % 128)
            bv = bv + BitVector(size=padding_bits)
        
       
        num_blocks = len(bv) // 128
        encrypted_blocks = []
        
        for i in range(num_blocks):
            # Extract a 128-bit block
            block = bv[i*128:(i+1)*128]
            
            # prepend 128 zeros to make it a 256-bit block
            padded_block = BitVector(size=128) + block
            
            # Convert block to integer for RSA encryption
            M = int(padded_block)
            print(f"Block {i}: {M}")
            # Apply RSA encryption: C = M^e mod n
            C = pow(M, self.e, self.n)
            
            encrypted_blocks.append(C)
        
        # Write encrypted blocks to file
        with open(ciphertext, 'w') as f:
            for block in encrypted_blocks:
                f.write(str(block) + '\n')

    def decrypt(self, ciphertext:str, recovered_plaintext:str) -> None:
        # read encrypted blocks from file
        with open(ciphertext, 'r') as f:
            encrypted_blocks = [int(line.strip()) for line in f.readlines()]
        
        decrypted_bits = BitVector(size=0)
        
        for C in encrypted_blocks:
            # use chinese remainder theorem
            
            # Calculate dp = d mod (p-1) and dq = d mod (q-1)
            dp = self.d % (self.p - 1)
            dq = self.d % (self.q - 1)
            
            # Calculate Mp = C^dp mod p and Mq = C^dq mod q
            Mp = pow(C, dp, self.p)
            Mq = pow(C, dq, self.q)
            
            # Calculate qInv = q^(-1) mod p
            qInv = self.mod_inv(self.q, self.p)
            
            # Apply CRT formula: M = (Mq + q * ((qInv * (Mp - Mq)) mod p)) mod n
            h = (qInv * (Mp - Mq)) % self.p
            M = (Mq + h * self.q) % self.n
            
            # Convert M to a 256-bit vector
            M_bits = BitVector(intVal=M, size=256)
            
            # Remove the 128 leading zeros we added during encryption
            actual_bits = M_bits[128:]
            
            # Add to our result
            decrypted_bits = decrypted_bits + actual_bits
        
        # Convert bit vector back to text and write to file
        with open(recovered_plaintext, 'w') as f:
            f.write(decrypted_bits.get_text_from_bitvector())

if __name__ == "__main__":
    cipher = RSA(e=65537)
    
    if len(sys.argv) >= 3 and sys.argv[1] == "-g":
        cipher.generate_keys(p_file=sys.argv[2], q_file=sys.argv[3])
        
    elif len(sys.argv) >= 6 and sys.argv[1] == "-e":
        cipher.read_keys(p_file=sys.argv[3], q_file=sys.argv[4])
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[5])
        
    elif len(sys.argv) >= 6 and sys.argv[1] == "-d":
        cipher.read_keys(p_file=sys.argv[3], q_file=sys.argv[4])
        cipher.decrypt(ciphertext=sys.argv[2], recovered_plaintext=sys.argv[5])
    else:
        print("Invalid command-line syntax.")
