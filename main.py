import argparse
from WalletKey import *
from WasabiKeyExtractor import *
from WhirlpoolKeyExtractor import *
from InfinityKeyExtractor import *
from GuardaKeyExtractor import *
from GreenKeyExtractor import *
from ExodusKeyExtractor import *
from AtomicKeyExtractor import *
from CoinomiKeyExtractor import *

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
        print('[-] Supported Wallet : atomic, coinomi, exodus, green, guarda, infinity, wasabi, whirlpool.')
    
    with open(file_path, 'rb') as f:
        print(f"[*] Reading {file_path}...")
        file = f.read() 

    if wallet == 'atomic':
        AtomicKeyExtractor(file).run()
    elif wallet == 'guarda':
        GuardaKeyExtractor(file).run()
    elif wallet == 'green':
        GreenKeyExtractor(file).run()
    elif wallet == 'exodus':
        ExodusKeyExtractor(file).run()
    elif wallet == 'coinomi':
        CoinomiKeyExtractor(file).run()
    elif wallet == 'infinity':
        InfinityKeyExtractor(file).run()
    elif wallet == 'whirlpool':
        WhirlpoolKeyExtractor(file).run()
    elif wallet == 'wasabi':
        WasabiKeyExtractor(file).run()

if __name__ == "__main__":
    main()

    