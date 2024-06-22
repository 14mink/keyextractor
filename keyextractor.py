import re
import sys
import base64
import math
import hmac
import binascii
from collections import Counter
from binascii import hexlify, unhexlify
from btclib import bip32, mnemonic
from btclib.mnemonic import bip39
from btclib.network import NETWORKS
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
import base58
import argparse

def extract_mnemonic_regex(file_path):
    with open(file_path, 'rb') as f:
        print(f"[*] Reading {file_path}...")
        file = f.read() 

        print("[*] Searching for mnemonic code...")
        MNEMONIC_REGEX=b'[a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}'
        mnemonic_candidates = regex_search(file,MNEMONIC_REGEX)

        print(f"[*] Verifying {len(mnemonic_candidates)} artifacts...")
        for i in range(len(mnemonic_candidates)):
            #print(f"\nVerifying Candidate [{i}]...")
            try:
                key = WalletKey(mnemonic=mnemonic_candidates[i].decode(), account_path="m/44'/0'/0'")
            except:
                continue
            if verify_key(file, key):
                key.print_keys()
                break
            else :
                continue
                #print("Failed to Verify")
            
def extract_wasabi(file_path):
    with open(file_path, 'rb') as f:
        print(f"[*] Reading {file_path}...")
        file = f.read() 

        print("[*] Searching for master chain code...")
        WASABI_PATTERN_1 = b'"ChainCode": "'
        chaincode = base64.b64decode(extract_key(file, WASABI_PATTERN_1, extract_type="END_PATTERN", end_pattern='"'))
        chaincode_hex = chaincode.hex()
        
        print("[*] Searching for master private key...")
        WASABI_PATTERN_2 = chaincode
        ecprv_candidates, _ = sort_by_entropy(extract_key(file, WASABI_PATTERN_2, extract_type="OFFSET", distance=-0x184, length=0x20, search_all=True, reverse=True))
        
        #print("\npossible master private key list")
        #for i in range(len(ecprv_candidates)):
        #    print(f'\t[{i}] : {ecprv_candidates[i].hex()}')

        print("[*] Verifying artifacts...")
        for i in range(len(ecprv_candidates)):
            #print(f"\nverifying artifact [{i}]...")
            key = WalletKey(ecprv=ecprv_candidates[i], chaincode=chaincode, account_path="m/84'/0'/0'")

            if verify_key(file, key):
                key.print_keys()
                break
            else :
                continue
                #print("failed to verify")
            
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
                key = WalletKey(mnemonic=mnemonic_candidates[i].decode(), passphrase=passphrase, account_path="m/44'/0'/0'")
            except:
                continue

            if verify_key(file, key):
                key.print_keys()
                break

            else :
                continue
                #print("Failed to Verify")

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
            key = WalletKey(ecprv=priv_cc_candidates[i]["ecprv"], chaincode=priv_cc_candidates[i]["cc"], account_path="m/44'/0'/0'")

            if verify_key(file, key):
                key.print_keys()
                break
            else :
                continue
                #print(f"failed to verify artifact[{i}]")

def aes_cbc_256_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def regex_search(file, regex):
    pattern_bytes = re.compile(regex)
    matches = pattern_bytes.findall(file)
    return matches

def calculate_entropy(binary_data):
    # Calculate frequency of each byte
    byte_frequency = Counter(binary_data)
    
    # Calculate probability of each byte
    total_bytes = len(binary_data)
    probabilities = [count / total_bytes for count in byte_frequency.values()]
    
    # Calculate entropy
    entropy = -sum(p * math.log2(p) for p in probabilities if p != 0)
    
    return entropy


def sort_by_entropy(list):
    entropy_values = [(hex_value, calculate_entropy(hex_value)) for hex_value in list]
    sorted_entropy_values = sorted(entropy_values, key=lambda x: x[1], reverse=True)
    sorted_hex_values = [hex_value for hex_value, _ in sorted_entropy_values]
    return sorted_hex_values, sorted_entropy_values


def search_pattern(file, pattern, search_all=False):
    offset_list = []
    offset = file.find(pattern)

    #if offset == -1:
    #    print("\t\tPattern",pattern.hex,"not found.")
    
    offset_list.append(offset)
    
    if search_all:
        while True:
            offset = file.find(pattern, offset + 1)
            if offset == -1:
                break
            offset_list.append(offset)

    return offset_list


def extract_key(file, pattern, search_all=False, extract_type='', end_pattern=0, distance=0, length=0, reverse=False):
    extracted_value_list = []
    offset_list = search_pattern(file, pattern, search_all=search_all)
    if offset_list[0] == -1:
        sys.exit()
    
    if extract_type == "END_PATTERN":
        for i in range(len(offset_list)):
            end_idx = file.find(end_pattern.encode(), offset_list[i] + len(pattern))
            if reverse == True:
                extracted_value = file[offset_list[i] + len(pattern):end_idx][::-1]
            else :
                extracted_value = file[offset_list[i] + len(pattern):end_idx]
            extracted_value_list.append(extracted_value)

    if extract_type == "OFFSET":
        for i in range(len(offset_list)):
            start_idx = offset_list[i] + distance 
            if reverse == True:
                extracted_value = file[start_idx : start_idx + length][::-1]
            else :
                extracted_value = file[start_idx : start_idx + length]
            extracted_value_list.append(extracted_value)
    
    dedup_extracted_value_list = list(set(extracted_value_list))
    if search_all==False:
        return dedup_extracted_value_list[0]
    return dedup_extracted_value_list

def mnemonic_from_entropy(entropy):
    mnemonic = bip39.mnemonic_from_entropy(entropy)
    return mnemonic

def entropy_from_mnemonic(mnemonic):
    entropy = bip39.entropy_from_mnemonic(mnemonic)
    hex_bytes = bytes([int(entropy[i:i+8], 2) for i in range(0, len(entropy), 8)])
    return hex_bytes

def seed_from_mnemonic(mnemonic, passphrase=""):
    seed = bip39.seed_from_mnemonic(mnemonic, passphrase)
    return seed

def key_from_seed(seed):
    hmac_ = hmac.new(b"Bitcoin seed", seed, "sha512").digest()
    ecprv = hmac_[:32]
    chaincode=hmac_[32:]
    xprv = bip32.rootxprv_from_seed(seed)
    return (ecprv, chaincode, xprv)


def xprv_from_ecprv_cc(ecprv, chaincode):
    network = NETWORKS["mainnet"]
    xkey_data = bip32.BIP32KeyData(
        version=network.bip32_prv,
        depth=0,
        parent_fingerprint=b'\x00'*4,
        index=0,
        chain_code=chaincode,
        key=b'\x00'+ecprv,
    )
    xprv = xkey_data.b58encode()
    return xprv


def account_xpub_from_xprv(xprv, derivation_path):             
    account_xprv = bip32.derive(xprv, derivation_path)
    account_xpub = bip32.xpub_from_xprv(account_xprv)
    return account_xpub

def account_cc_from_xprv(xprv, derivation_path):
    account_xprv = bip32.derive(xprv, derivation_path)
    account_xprv_bytes=base58.b58decode(account_xprv)
    account_cc = account_xprv_bytes[13:45]
    return account_cc

class WalletKey:

    def __init__(self, entropy='', mnemonic='', passphrase='', seed=b'', xprv='', ecprv=b'', chaincode=b'', account_path=''):
        self.entropy = entropy
        self.mnemonic = mnemonic
        self.passphrase = passphrase
        self.seed = seed
        self.xprv = xprv
        self.ecprv = ecprv
        self.chaincode = chaincode
        self.account_path = account_path
        self.account_xpub = ''
        self.account_cc = b''
        self.candidate = ""

        if entropy:
            self.mnemonic = mnemonic_from_entropy(entropy)
            self.seed = seed_from_mnemonic(self.mnemonic,passphrase)
            self.ecprv, self.chaincode, self.xprv = key_from_seed(self.seed)
            self.candidate = "entropy"
        
        if mnemonic:
            self.entropy = entropy_from_mnemonic(mnemonic)
            self.seed = seed_from_mnemonic(mnemonic,passphrase)
            self.ecprv, self.chaincode, self.xprv = key_from_seed(self.seed)
            self.candidate = "mnemonic"

        if seed:
            self.ecprv, self.chaincode, self.xprv = key_from_seed(seed)
            self.candidate = "seed"

        if ecprv and chaincode:
            self.xprv = xprv_from_ecprv_cc(ecprv, chaincode)
            self.candidate = "ecprv_cc"
        
        if account_path:
            self.account_xpub = account_xpub_from_xprv(self.xprv, account_path)
            self.account_cc = account_cc_from_xprv(self.xprv, account_path)


    def print_keys(self):
        print("\n[+] Wallet info")
        #if self.entropy:
            #print(f"\tentropy : {self.entropy.hex()}")
        if self.mnemonic:
            print(f"\tmnemonic code : {self.mnemonic}")
        if self.passphrase:
            print(f"\tbip39 passphrase : {self.passphrase}")
        #if self.seed:
            #print(f"\tmaster seed : {self.seed.hex()}")
        if self.xprv:
            print(f"\tmaster xprv : {self.xprv}")
        #if self.ecprv:
            #print(f"\tmaster private key : {self.ecprv.hex()}")
        #if self.chaincode:
            #print(f"\tmaster chain code : {self.chaincode.hex()}")
        #if self.account_xpub:
            #print(f"\taccount xpub : {self.account_xpub}")
        print("\n")


def verify_key(file, key: WalletKey):
    if key.candidate == "entropy" :
        #print(f"\tsearching for mnemonic code...")
        #offset = search_pattern(file, key.mnemonic.encode())[0]
        #if offset != -1:
        #    print(f"\tmnemonic code({key.mnemonic}) found at offset {hex(offset)}")
        #    return True

        #print(f"\tsearching for master seed...")
        offset = search_pattern(file, key.seed)[0]
        if offset != -1:
            print(f"\tmaster seed({key.seed.hex()}) found at offset {hex(offset)}")
            return True

        #print(f"\tsearching for master private key...")
        offset = search_pattern(file, key.ecprv)[0]
        if offset != -1:
            print(f"\tmaster private key({key.ecprv.hex()}) found at offset {hex(offset)}")
            return True
        
        #print(f"\tsearching for master chain code...")
        offset = search_pattern(file, key.chaincode)[0]
        if offset  != -1:
            print(f"\tmaster chain code({key.chaincode.hex()}) found at offset {hex(offset)}")
            return True
        
        #print(f"\tsearching for account xpub...")
        offset = search_pattern(file, key.account_xpub.encode())[0]
        if offset != -1:
            print(f"\taccount xpub({key.account_xpub}) found at offset {hex(offset)}")
            return True
        
    if key.candidate == "mnemonic":
        #print(f"\tsearching for entropy...")
        #offset = search_pattern(file, key.entropy)[0]
        #if offset != -1:
        #    print(f"\tentropy({key.entropy.hex()}) found at offset {hex(offset)}")
        #    return True

        #print(f"\tsearching for master seed...")
        offset = search_pattern(file, key.seed)[0]
        if offset != -1:
            print(f"\tseed({key.seed.hex()}) found at offset {hex(offset)}")
            return True

        #print(f"\tsearching for master private key...")
        offset = search_pattern(file, key.ecprv)[0]
        if offset != -1:
            print(f"\tmaster private key({key.ecprv.hex()}) found at offset {hex(offset)}")
            return True
        
        #print(f"\tsearching for master chain code...")
        offset = search_pattern(file, key.chaincode)[0]
        if offset  != -1:
            print(f"\tmaster chain code({key.chaincode.hex()}) found at offset {hex(offset)}")
            return True
        
        #print(f"\tsearching for account xpub...")
        offset = search_pattern(file, key.account_xpub.encode())[0]
        if offset != -1:
            print(f"\taccount xpub({key.account_xpub}) found at offset {hex(offset)}")
            return True
    
    if key.candidate == "seed":
        #print(f"\tsearching for master private key...")
        offset = search_pattern(file, key.ecprv)[0]
        if offset != -1:
            print(f"\tmaster private key({key.ecprv.hex()}) found at offset {hex(offset)}")
            return True
        
        #print(f"\tsearching for master chain code...")
        offset = search_pattern(file, key.chaincode)[0]
        if offset  != -1:
            print(f"\tmaster chain code({key.chaincode.hex()}) found at offset {hex(offset)}")
            return True
        
        #print(f"\tsearching for account xpub...")
        offset = search_pattern(file, key.account_xpub.encode())[0]
        if offset != -1:
            print(f"\taccount xpub({key.account_xpub}) found at offset {hex(offset)}")
            return True
    
    if key.candidate == "ecprv_cc":
        #print(f"\tsearching for account xpub...")
        offset = search_pattern(file, key.account_xpub.encode())[0]
        if offset != -1:
            print(f"\taccount xpub({key.account_xpub}) found at offset {hex(offset)}")
            return True
        
        #print(f"\tsearching for account private key...")
        offset = search_pattern(file, key.account_cc)[0]
        if offset != -1:
            print(f"\taccount chain code({key.account_cc.hex()}) found at offset {hex(offset)}")
            return True
        
           
    return False

def main():
    parser = argparse.ArgumentParser(description='Process some arguments.')
    parser.add_argument('-f', '--file', metavar='FILE', type=str, help='Specify target file')
    parser.add_argument('-w', '--wallet', metavar='WALLET', type=str, help='Specify target wallet')
    args = parser.parse_args()
    file_path, wallet = "", ""

    if args.file:
        file_path=args.file
    else:
        print('[-] No target file specified.')

    if args.wallet in ("atomic", "coinomi", "exodus", "green", "guarda", "infinity", "wasabi", "whirlpool"):
        wallet=args.wallet
    else:
        print('[-] Supported Wallet Program : atomic, coinomi, exodus, green, guarda, infinity, wasabi, whirlpool.')

    if wallet in ("atomic", "exodus", "green", "guarda", "infinity"):
        extract_mnemonic_regex(file_path)
    elif wallet == "wasabi":
        extract_wasabi(file_path)
    elif wallet == "whirlpool":
        extract_whirlpool(file_path)
    elif wallet == "coinomi":
        extract_coinomi(file_path)


if __name__ == "__main__":
    main()

    