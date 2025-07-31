import hashlib
import time
import json

# Hypothetical SPHINCS+ and NTRU libraries
class Sphincs:
    def generate_keypair(self):
        # Simulate key generation
        private_key = hashlib.sha256("SPHINCS+_SK".encode()).hexdigest()
        public_key = hashlib.sha256("SPHINCS+_PK".encode()).hexdigest()
        return private_key, public_key

    def sign(self, message_hash, private_key):
        # Simulate signing with private key and message hash
        return hashlib.sha256((message_hash + private_key).encode()).hexdigest()

    def verify(self, message_hash, signature, public_key):
        # Simulate verification
        expected_signature = hashlib.sha256((message_hash + public_key).encode()).hexdigest()
        return signature == expected_signature


class NTRUEncrypt:
    def generate_keypair(self):
        # Simulate key generation
        private_key = hashlib.sha256("NTRU_SK".encode()).hexdigest()
        public_key = hashlib.sha256("NTRU_PK".encode()).hexdigest()
        return private_key, public_key

    def encrypt(self, data, public_key):
        # Simulate encryption with public key
        return hashlib.sha256((data + public_key).encode()).hexdigest()

    def decrypt(self, ciphertext, private_key):
        # Simulate decryption (simplified for testing)
        return hashlib.sha256((ciphertext + private_key).encode()).hexdigest()


# Hybrid Digital Signature Class
class HybridSignature:
    def __init__(self):
        # Initialize SPHINCS+ and NTRU
        self.sphincs = Sphincs()
        self.ntru = NTRUEncrypt()
        
        # Generate key pairs
        self.sp_sk, self.sp_pk = self.sphincs.generate_keypair()
        self.ntru_sk, self.ntru_pk = self.ntru.generate_keypair()

    def sign(self, message):
        # Hash the message
        message_hash = hashlib.sha256(message.encode()).hexdigest()
        
        # SPHINCS+ signing
        sp_signature = self.sphincs.sign(message_hash, self.sp_sk)
        
        # NTRU encryption of SPHINCS+ signature
        ntru_cipher = self.ntru.encrypt(sp_signature, self.ntru_pk)
        
        # Return hybrid signature as a dictionary
        return {"sphincs_sig": sp_signature, "ntru_cipher": ntru_cipher}

    def verify(self, message, signature):
        # Extract components from signature
        sp_signature = signature["sphincs_sig"]
        ntru_cipher = signature["ntru_cipher"]
        
        # Decrypt NTRU cipher to verify integrity
        decrypted_ntru = self.ntru.decrypt(ntru_cipher, self.ntru_sk)
        
        # Verify SPHINCS+ signature
        message_hash = hashlib.sha256(message.encode()).hexdigest()
        sphincs_valid = self.sphincs.verify(message_hash, sp_signature, self.sp_pk)
        
        # Check if decrypted NTRU matches original SPHINCS+ signature (simplified)
        return sphincs_valid and decrypted_ntru == hashlib.sha256((sp_signature + self.ntru_sk).encode()).hexdigest()


# Block Class
class Block:
    def __init__(self, index, previous_hash, timestamp, data, nonce=0, signature=None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.nonce = nonce
        self.signature = signature
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        # Create a string of all block attributes and hash it
        block_string = json.dumps({
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "data": self.data,
            "nonce": self.nonce,
            "signature": self.signature
        }, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()


# Blockchain Class
class Blockchain:
    def __init__(self):
        self.chain = []
        self.difficulty = 2  # Reduced for faster testing
        self.hybrid_signer = HybridSignature()  # Initialize hybrid signature system
        self.create_genesis_block()

    def create_genesis_block(self):
        # Create and sign the genesis block
        genesis_data = "Genesis Block"
        signature = self.hybrid_signer.sign(genesis_data)
        genesis_block = Block(0, "0", time.time(), genesis_data, 0, signature)
        self.chain.append(genesis_block)

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        previous_block = self.get_latest_block()
        
        # Sign the data using the hybrid signature system
        signature = self.hybrid_signer.sign(data)
        
        # Create a new block
        new_block = Block(
            previous_block.index + 1,
            previous_block.hash,
            time.time(),
            data,
            signature=signature
        )
        
        # Mine the block
        start_time = time.time()
        new_block = self.mine_block(new_block)
        mining_time = time.time() - start_time
        return new_block, mining_time

    def mine_block(self, block):
        target = "0" * self.difficulty
        while block.hash[:self.difficulty] != target:
            block.nonce += 1
            block.hash = block.calculate_hash()
        print(f"Block mined! Nonce: {block.nonce}")
        return block

    def is_chain_valid(self):
        start_time = time.time()
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Verify current block's hash
            if current.hash != current.calculate_hash():
                print(f"Invalid hash at block {i}")
                return False

            # Verify previous block hash link
            if current.previous_hash != previous.hash:
                print(f"Invalid previous hash at block {i}")
                return False

            # Verify proof of work
            if current.hash[:self.difficulty] != "0" * self.difficulty:
                print(f"Invalid proof of work at block {i}")
                return False

            # Verify the digital signature
            if not self.hybrid_signer.verify(current.data, current.signature):
                print(f"Invalid signature at block {i}")
                return False

        validation_time = time.time() - start_time
        print(f"Validation time: {validation_time:.4f} seconds")
        return True


# Example usage
def main():
    # Create a new blockchain
    my_blockchain = Blockchain()
    
    # Add some blocks
    print("Mining block 1...")
    block1, time1 = my_blockchain.add_block("Transaction 1: Alice sends 10 coins to Bob")
    
    print("Mining block 2...")
    block2, time2 = my_blockchain.add_block("Transaction 2: Bob sends 5 coins to Charlie")
    
    # Print the blockchain
    for block in my_blockchain.chain:
        print("\nBlock Details:")
        print(f"Index: {block.index}")
        print(f"Previous Hash: {block.previous_hash}")
        print(f"Hash: {block.hash}")
        print(f"Data: {block.data}")
        print(f"Timestamp: {block.timestamp}")
        print(f"Nonce: {block.nonce}")
        print(f"Signature: {json.dumps(block.signature, indent=2)}")

    # Verify blockchain integrity
    print("\nIs blockchain valid?", my_blockchain.is_chain_valid())
    print(f"Transaction 1 mining time: {time1:.4f} seconds")
    print(f"Transaction 2 mining time: {time2:.4f} seconds")
    print(f"Throughput: {2 / (time1 + time2):.2f} tx/s")


if __name__ == "__main__":
    main()