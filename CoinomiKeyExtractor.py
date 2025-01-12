from WalletKey import *
from KeyExtractor import *

class CoinomiKeyExtractor(KeyExtractor):
    def __init__(self,mem):
        self.mem = mem
        self.keys = []
    
    def run(self):
        candidates = self.extract()
        self.verify(candidates)

    def extract(self):
        #object_header=b'\x01\x00\x00\x00\x00\x00\x00\x00\xf5\x00\x00\x20'
        
        print("[*] Searching for object header...")
        COINOMI_PATTERN_HEADER = b'\x07\x00\x00\x00mandate'
        object_header = extract_key(self.mem, COINOMI_PATTERN_HEADER, extract_type="OFFSET", distance=-0xc, length=0xc)[1:]
        
        aeskey_candidates, hdkey_candidates, priv_cc_candidates = [], [], []
        aeskey_offset, iv_offset, enc_priv_offset, cc_offset = 0x10, 0x10, 0x30, 0x70
        aeskey_len, iv_len, enc_priv_len, cc_len = 0x20, 0x10, 0x30, 0x20
        
        print("[*] Searching for aeskey...")
        COINOMI_PATTERN_AESKEY = b'.'+ object_header + b'\x20\x00\x00\x00.{32}.{24}' + b'.'+object_header + b'\x20\x00\x00\x00.{32}.{16}' + b'.'+object_header + b'.\x00\x00\x00'
        aeskey_matched_list = list(set(regex_search(self.mem,COINOMI_PATTERN_AESKEY)))
        
        for aeskey_matched in aeskey_matched_list:
            aeskey_candidates.append(aeskey_matched[aeskey_offset:aeskey_offset+aeskey_len])
        aeskey_candidates = list(set(aeskey_candidates))

        print("[*] Searching for deterministickey...")
        COINOMI_PATTERN_HDKEY = b'.'+object_header + b'\x10\x00\x00\x00.{16}' + b'.'+object_header + b'\x30\x00\x00\x00.{48}' + b'.'+ object_header + b'\x20\x00\x00\x00.{32}'
        hdkey_matched_list = list(set(regex_search(self.mem,COINOMI_PATTERN_HDKEY)))

        for hdkey_matched in hdkey_matched_list:
            hdkey_candidates.append({"iv" : hdkey_matched[iv_offset:iv_offset+iv_len], "enc_priv" : hdkey_matched[enc_priv_offset:enc_priv_offset+enc_priv_len], "cc" : hdkey_matched[cc_offset:cc_offset+cc_len]})

        for aeskey in aeskey_candidates:
            for hdkey in hdkey_candidates:
                priv_cc_candidates.append({"ecprv" : aes_cbc_256_decrypt(hdkey["enc_priv"], aeskey, hdkey["iv"]), "cc": hdkey["cc"]})

        return priv_cc_candidates
        
    def validate(self, candidate):
        print(f"\nverifying artifact: [{candidate}]...")
        try:
            key = WalletKey(ecprv=candidate["ecprv"], chaincode=candidate["cc"])
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
                continue


'''
def extract_coinomi(file_path):
    with open(file_path, 'rb') as f:
        print(f"[*] Reading {file_path}...")
        file = f.read() 
        
        #object_header=b'\x01\x00\x00\x00\x00\x00\x00\x00\xf5\x00\x00\x20'
        
        print("[*] Searching for object header...")
        COINOMI_PATTERN_HEADER = b'\x07\x00\x00\x00mandate'
        object_header = extract_key(file, COINOMI_PATTERN_HEADER, extract_type="OFFSET", distance=-0xc, length=0xc)[1:]
        
        aeskey_candidates, hdkey_candidates, priv_cc_candidates = [], [], []
        aeskey_offset, iv_offset, enc_priv_offset, cc_offset = 0x10, 0x10, 0x30, 0x70
        aeskey_len, iv_len, enc_priv_len, cc_len = 0x20, 0x10, 0x30, 0x20
        
        print("[*] Searching for aeskey...")
        COINOMI_PATTERN_AESKEY = b'.'+ object_header + b'\x20\x00\x00\x00.{32}.{24}' + b'.'+object_header + b'\x20\x00\x00\x00.{32}.{16}' + b'.'+object_header + b'.\x00\x00\x00'
        aeskey_matched_list = list(set(regex_search(file,COINOMI_PATTERN_AESKEY)))
        
        for aeskey_matched in aeskey_matched_list:
            aeskey_candidates.append(aeskey_matched[aeskey_offset:aeskey_offset+aeskey_len])
        aeskey_candidates = list(set(aeskey_candidates))

        print("[*] Searching for deterministickey...")
        COINOMI_PATTERN_HDKEY = b'.'+object_header + b'\x10\x00\x00\x00.{16}' + b'.'+object_header + b'\x30\x00\x00\x00.{48}' + b'.'+ object_header + b'\x20\x00\x00\x00.{32}'
        hdkey_matched_list = list(set(regex_search(file,COINOMI_PATTERN_HDKEY)))

        for hdkey_matched in hdkey_matched_list:
            hdkey_candidates.append({"iv" : hdkey_matched[iv_offset:iv_offset+iv_len], "enc_priv" : hdkey_matched[enc_priv_offset:enc_priv_offset+enc_priv_len], "cc" : hdkey_matched[cc_offset:cc_offset+cc_len]})

        for aeskey in aeskey_candidates:
            for hdkey in hdkey_candidates:
                priv_cc_candidates.append({"ecprv" : aes_cbc_256_decrypt(hdkey["enc_priv"], aeskey, hdkey["iv"]), "cc": hdkey["cc"]})

        print(f"[*] Verifying {len(priv_cc_candidates)} artifacts...")
        for i in range(len(priv_cc_candidates)):
            #print(f"\nverifying artifact [{i}]...")
            #print(f'ecprv={priv_cc_candidates[i]["ecprv"].hex()}')
            key = WalletKey(ecprv=priv_cc_candidates[i]["ecprv"], chaincode=priv_cc_candidates[i]["cc"])

            if verify_key(file, key):
                key.print_keys()
                break
            else :
                continue
                #print(f"failed to verify artifact[{i}]")
'''