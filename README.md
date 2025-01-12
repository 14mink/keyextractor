# keyextractor

### supported wallet
- atomic wallet
- blockstream green
- coinomi
- exodus
- guarda
- infinity wallet
- wasabi wallet
- whirlpool

### usage
```python keyextractor.py --wallet <atomic, green, coinomi, exodus, guarda, infinity, wasabi, whirlpool> --file <memory dump file path>```
**Only for full memory dump file**

### latest check
- whirlpool : banned
- wasabi : O (bip39 passphrase set)
- green : O
- atomic : O
- guarda : O (unverified)
- infinity : O
- coinomi : X
- exodus : There is case where mnemonic code is not stored on memory


python main.py --wallet wasabi --file C:\Users\USER\Desktop\ram\wasabi_after_login.mem

