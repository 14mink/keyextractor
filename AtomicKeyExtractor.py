from WalletKey import *
from KeyExtractor import *

class AtomicKeyExtractor(KeyExtractor):
    pass


'''
def extract_mnemonic_regex(mem_file_path):
    with open(mem_file_path, 'rb') as f:
        print(f"[*] Reading {mem_file_path}...")
        mem = f.read() 

        print("[*] Searching for mnemonic code...")
        MNEMONIC_REGEX=b'[a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}'
        mnemonic_candidates = list(set(regex_search(mem,MNEMONIC_REGEX)))

        print(f"[*] Verifying {len(mnemonic_candidates)} artifacts...")
        unverified_candidates = []
        for i in range(len(mnemonic_candidates)):
            print(f"\nVerifying Candidate [{i}] : [{mnemonic_candidates[i]}]...")
            try:
                key = WalletKey(mnemonic=mnemonic_candidates[i].decode())
            except Exception as e:
                #print(e)
                print("Invalid Mnemonic Code")
                continue
            if verify_key(mem, key):
                print("Artifact Verified")
                key.print_keys()
                break
            else :
                unverified_candidates.append(mnemonic_candidates[i])
                continue
                #print("Failed to Verify")
        if len(unverified_candidates) > 0:
            unverified_candidates = list(set(unverified_candidates))
            print(f'[*] {len(unverified_candidates)} valid but unverified mnemonic code(s).')
            print(f'\t({i+1}) {unverified_candidates[i].decode()}' for i in range(len(unverified_candidates)))
'''