from WalletKey import *
from collections import Counter
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import math
import re

class KeyExtractor():
    def __init__(self,mem):
        self.mem = mem
        self.keys = []
    
    def run(self):
        candidates = self.extract()
        self.verify(candidates)

    def extract(self):
        mnemonic_candidates = list(set(regex_search(self.mem,MNEMONIC_REGEX)))
        return mnemonic_candidates
    
    def validate(self, candidate):
        print(f"\nverifying artifact: [{candidate}]...")
        try:
            key = WalletKey(mnemonic=candidate.decode())
        except Exception as e:
            print(e)
            return
        return key
                
    def verify(self, candidates):
        unverified_candidates = []
        for candidate in candidates:
            key = self.validate(candidate)
            if not key: continue
            
            if self.verify_key(key):
                print("\tVerified !")
                key.print_keys()
                break
            else :
                unverified_candidates.append(candidate)
                continue
                
        if unverified_candidates:
            unverified_candidates = list(set(unverified_candidates))
            print(f'[*] {len(unverified_candidates)} valid but unverified mnemonic code(s).')
            for idx, unverified_candidate in enumerate(unverified_candidates):
                print(f'\t({idx+1}) {unverified_candidate.decode()}')

    def verify_key(self, key: WalletKey):
        if key.candidate == ENTROPY :
            if self.search_verifying_artifact(key.mnemonic, MNEMONIC_CODE): return True
            if self.search_verifying_artifact(key.seed, MASTER_SEED): return True
            if self.search_verifying_artifact(key.ecprv, MASTER_PRIVATE_KEY): return True
            if self.search_verifying_artifact(key.chaincode, MASTER_CHAIN_CODE): return True
            if self.search_verifying_artifact(key.btc_acc_xpubs, ACCOUNT_EXT_PUBLIC_KEY): return True
        
        if key.candidate == MNEMONIC_CODE :
            if self.search_verifying_artifact(key.entropy, ENTROPY): return True
            if self.search_verifying_artifact(key.seed, MASTER_SEED): return True
            if self.search_verifying_artifact(key.ecprv, MASTER_PRIVATE_KEY): return True
            if self.search_verifying_artifact(key.chaincode, MASTER_CHAIN_CODE): return True
            if self.search_verifying_artifact(key.btc_acc_xpubs, ACCOUNT_EXT_PUBLIC_KEY): return True 

        if key.candidate == MASTER_SEED:
            if self.search_verifying_artifact(key.ecprv, MASTER_PRIVATE_KEY): return True
            if self.search_verifying_artifact(key.chaincode, MASTER_CHAIN_CODE): return True
            if self.search_verifying_artifact(key.btc_acc_xpubs, ACCOUNT_EXT_PUBLIC_KEY): return True 

        if key.candidate == ECPRV_CC:
            if self.search_verifying_artifact(key.btc_acc_xpubs, ACCOUNT_EXT_PUBLIC_KEY): return True 

        return False  

    def search_verifying_artifact(self, artifact, artifact_type):
        print(f"\tsearching for {artifact_type}...")

        if artifact_type == MNEMONIC_CODE:
            offset = search_pattern(self.mem, artifact.encode())[0]
            if offset != -1:
                print(f"\t{artifact_type}({artifact}) found at offset {hex(offset)}")
                return True
            
        elif artifact_type == ENTROPY or artifact_type == MASTER_SEED or artifact_type == MASTER_CHAIN_CODE or artifact_type == MASTER_PRIVATE_KEY:
            offset = search_pattern(self.mem, artifact)[0]
            if offset != -1:
                print(f"\t{artifact_type}({artifact.hex()}) found at offset {hex(offset)}")
                return True
            
        elif artifact_type == ACCOUNT_EXT_PUBLIC_KEY:
            for xpub in artifact:
                #print(f'xpub : {xpub}')
                offset = search_pattern(self.mem, xpub.encode())[0]
                if offset != -1:
                    print(f"\t{artifact_type}({xpub}) found at offset {hex(offset)}")
                    return True 


def sort_by_entropy(list):
    entropy_values = [(hex_value, get_entropy(hex_value)) for hex_value in list]
    sorted_entropy_values = sorted(entropy_values, key=lambda x: x[1], reverse=True)
    sorted_hex_values = [hex_value for hex_value, _ in sorted_entropy_values]
    return sorted_hex_values, sorted_entropy_values

def get_entropy(data):
    byte_frequency = Counter(data)
    probabilities = [count / len(data) for count in byte_frequency.values()]
    entropy = -sum(p * math.log2(p) for p in probabilities if p != 0)
    return entropy

def aes_cbc_256_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def regex_search(file, regex):
    pattern_bytes = re.compile(regex)
    matches = pattern_bytes.findall(file)
    return matches