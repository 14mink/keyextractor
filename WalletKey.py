from btclib import bip32
from btclib.mnemonic import bip39
from btclib.network import NETWORKS
import hmac
import base58
import sys

ENTROPY = "entropy"
MNEMONIC_CODE = "mnemonic code"
MASTER_SEED = "master seed"
MASTER_PRIVATE_KEY = "master private key"
MASTER_CHAIN_CODE = "master chain code"
ECPRV_CC = "ecprv_cc"
ACCOUNT_EXT_PUBLIC_KEY = "account xpub"
MNEMONIC_REGEX = b'[a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}[ ][a-z]{3,8}'

class WalletKey:

    def __init__(self, entropy='', mnemonic='', passphrase='', seed=b'', xprv='', ecprv=b'', chaincode=b'', account_path=''):
        self.entropy = entropy
        self.mnemonic = mnemonic
        self.passphrase = passphrase
        self.seed = seed
        self.xprv = xprv
        self.ecprv = ecprv
        self.chaincode = chaincode

        if entropy:
            self.mnemonic = mnemonic_from_entropy(entropy)
            self.seed = seed_from_mnemonic(self.mnemonic,passphrase)
            self.ecprv, self.chaincode, self.xprv = key_from_seed(self.seed)
            self.candidate = ENTROPY
        
        if mnemonic:
            self.entropy = entropy_from_mnemonic(mnemonic)
            self.seed = seed_from_mnemonic(mnemonic,passphrase)
            self.ecprv, self.chaincode, self.xprv = key_from_seed(self.seed)
            self.candidate = MNEMONIC_CODE

        if seed:
            self.ecprv, self.chaincode, self.xprv = key_from_seed(seed)
            self.candidate = MASTER_SEED

        if ecprv and chaincode:
            self.xprv = xprv_from_ecprv_cc(ecprv, chaincode)
            self.candidate = ECPRV_CC
        
        self.btc_acc_xpub_32 = account_xpub_from_xprv(self.xprv,"m/32'/0'/0'")
        self.btc_acc_xpub_44 = account_xpub_from_xprv(self.xprv,"m/44'/0'/0'")
        self.btc_acc_xpub_49 = account_xpub_from_xprv(self.xprv,"m/49'/0'/0'")
        self.btc_acc_xpub_84 = account_xpub_from_xprv(self.xprv,"m/84'/0'/0'")
        self.btc_acc_cc_32 = account_cc_from_xprv(self.xprv,"m/32'/0'/0'")
        self.btc_acc_cc_44 = account_cc_from_xprv(self.xprv,"m/44'/0'/0'")
        self.btc_acc_cc_49 = account_cc_from_xprv(self.xprv,"m/49'/0'/0'")
        self.btc_acc_cc_84 = account_cc_from_xprv(self.xprv,"m/84'/0'/0'")
        self.btc_acc_xpubs = [self.btc_acc_xpub_32, self.btc_acc_xpub_44, self.btc_acc_xpub_49, self.btc_acc_xpub_84]

    def print_keys(self):
        print("\n[+] Wallet info")
        if self.entropy:
            print(f"\tentropy : {self.entropy.hex()}")
        if self.mnemonic:
            print(f"\tmnemonic code : {self.mnemonic}")
        if self.passphrase:
            print(f"\tbip39 passphrase : {self.passphrase}")
        if self.seed:
            print(f"\tmaster seed : {self.seed.hex()}")
        if self.xprv:
            print(f"\tmaster xprv : {self.xprv}")
        if self.ecprv:
            print(f"\tmaster private key : {self.ecprv.hex()}")
        if self.chaincode:
            print(f"\tmaster chain code : {self.chaincode.hex()}")
        print("\n")


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
    
    distinct_extracted_value_list = list(set(extracted_value_list))
    if search_all==False:
        return distinct_extracted_value_list[0]
    return distinct_extracted_value_list

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