from WalletKey import *
from KeyExtractor import *

class WhirlpoolKeyExtractor(KeyExtractor):
    def __init__(self,mem):
        self.mem = mem
        self.pattern_1 = b'{"seedPassphrase":"'
        self.passphrase = ""
        self.keys = []
    
    def run(self):
        candidates = self.extract()
        self.verify(candidates)

    def extract(self):
        print("[*] Searching for master chain code...")
        self.passphrase = (extract_key(self.mem, self.pattern_1, extract_type="END_PATTERN", end_pattern = '"')).decode('utf-8')

        MNEMONIC_REGEX=b'[a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}'
        mnemonic_candidates = regex_search(self.mem,MNEMONIC_REGEX)
        
        print("\npossible mnemonic codes")
        print(f'\t[{idx}] : {candidate.hex()}' for idx, candidate in enumerate(mnemonic_candidates))

        return mnemonic_candidates
    
    def validate(self, candidate):
        print(f"\nverifying artifact: [{candidate}]...")
        try:
            key = WalletKey(mnemonic=candidate.decode(), passphrase=self.passphrase)
        except Exception as e:
            print(e)
            return
        return key
                
    def verify(self, candidates):
        for candidate in candidates:
            key = self.validate(candidate)
            if not key: continue
            
            if super(self.mem).verify_key(key):
                print("Artifact Verified")
                key.print_keys()
                break

            else :
                print("Artifact Not verified")
                key.print_keys()
                continue

'''
def extract_whirlpool(file_path):
    with open(file_path, 'rb') as f:
        print(f"[*] Reading {file_path}...")
        file = f.read() 

        print("[*] Searching for bip39 passphrase...")
        WHIRLPOOL_PATTERN_1 = b'{"seedPassphrase":"'
        passphrase = (extract_key(file, WHIRLPOOL_PATTERN_1, extract_type="END_PATTERN", end_pattern = '"')).decode('utf-8')

        print("[*] Searching for mnemonic code...")
        MNEMONIC_REGEX=b'[a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}'
        mnemonic_candidates = regex_search(file,MNEMONIC_REGEX)

        print("[*] Verifying artifacts...")
        for i in range(len(mnemonic_candidates)):
        
            try:
                key = WalletKey(mnemonic=mnemonic_candidates[i].decode(), passphrase=passphrase)
            except:
                continue

            if verify_key(file, key):
                key.print_keys()
                break

            else :
                continue
                #print("Failed to Verify")
'''