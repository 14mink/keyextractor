from WalletKey import *
from KeyExtractor import *
import base64

class WasabiKeyExtractor(KeyExtractor):
    def __init__(self,mem):
        self.mem = mem
        self.pattern_1 = b'"ChainCode": "'
        self.chaincode = ""
        self.keys = []
    
    def run(self):
        candidates = self.extract()
        self.verify(candidates)

    def extract(self):
        ''' 1. Search for pattern "ChainCode": "<base64 encoded chain code>", then decode chain code '''
        print("[*] Searching for master chain code...")
        self.chaincode = base64.b64decode(extract_key(self.mem, self.pattern_1, extract_type="END_PATTERN", end_pattern='"'))

        ''' 2. Search for master xprv, where the length is 0x10, the offset is 0x184 ahead from chain code, and stored in reverse order. '''
        print("[*] Searching for master private key...")
        ecprv_candidates, _ = sort_by_entropy(extract_key(self.mem, self.chaincode, extract_type="OFFSET", distance=-0x184, length=0x20, search_all=True, reverse=True))
        
        print("\npossible master private key list")
        for idx, candidate in enumerate(ecprv_candidates):
            print(f'\t[{idx}] : {candidate.hex()}') 

        return ecprv_candidates
    
    def validate(self, candidate):
        print(f"\nverifying artifact: [{candidate.hex()}]...")
        try:
            key = WalletKey(ecprv=candidate, chaincode=self.chaincode)
        except Exception as e:
            print(e)
            return
        return key
                
    def verify(self, candidates):
        for candidate in candidates:
            key = self.validate(candidate)
            if not key: continue
            
            if self.verify_key(key):
                print("Artifact Verified")
                key.print_keys()
                break

            else :
                print("Artifact Not verified")
                key.print_keys()
                continue