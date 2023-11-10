from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from charm.core.engine.util import objectToBytes, bytesToObject
import hashlib
import charm.toolbox.ecgroup
import math


class IMDS_PKG:
    # Initiating the group and master key
    def __init__(self) -> None:
        # self.curve_name = 'secp256r1'
        self.group = PairingGroup('SS512')
        self.q = self.group.order()
        print(f'Params : {self.group.param}')
        print(f'q : {self.q}')
        print(f'q_bits : {int(math.ceil(math.log2(self.q)))}')
    
    # Define the bilinear map
    def e(self, a, b):
        return pair(a, b)

    # Map to point hash function
    def H0(self, input_str):
        return self.group.hash(input_str, G1)
    
    # General hash function
    def H1(self, input_str):
        return self.group.hash(input_str, ZR)
    
    # SHA256 hash function
    def H2(self, input_str):
        if type(input_str)!='bytes':
            input_str= bytes(str(input_str), 'utf-8')
        hash_object = hashlib.sha256()
        hash_object.update(input_str)
        sha256_hash = hash_object.hexdigest()
        return sha256_hash
    
    def generate_params(self):
        self.q = self.group.order()
        self.P = self.group.random(G1)
        self.P1 = self.group.random(G1)

        # Master secret key
        self.s = self.group.random(ZR)
        # Master public key
        self.P0 = self.s * self.P

        # Step 6: Publish public parameters
        public_parameters = {
            'q': self.q,
            'G1': G1,
            'G2': G2,
            'P': self.P,
            'P1': self.P1,
            'e': self.e,
            'H0': self.H0,
            'H1': self.H1,
            'H2': self.H2,
            'P0': self.P0,
            's':self.s,
            'group':self.group
        } 
        return public_parameters      


# point = pkg.H0("apple")
# print(f'map to point {point}')
# # To test if the public and private key are generated properly
# skt, qkt = pkg.generateUser("dt123@gmail.com")
# print(skt)
# print(qkt)
# ski, qki = pkg.generateUser("doi")
# print(ski)
# print(qki)

# # To test if pairing is working properly
# a = pkg.group.random(G1)
# b = pkg.group.random(G1)
# c = pkg.e(a,b)
# print(c)

# # To test the encrypt function
# medical_record = {
#     "name": "User",
#     "data": "sensitive data"
# }

# The public_parameters dictionary can be used for cryptographic operations

# Example usage of the bilinear map:
# use public parameters
# A = group.random(G1)
# B = group.random(G1)
# result = public_parameters['e'](A, B)
# print(result)
# # Example usage of hash functions:
# message = "Hello, Charm-Crypto!"
# hash_result = public_parameters['H0'](message)
# print("Hash of the message:", hash_result)

# print('Public Parameters')
# print(public_parameters)
