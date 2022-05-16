![xBrain Wallet Bitcoin Crack PrivateKey](https://raw.githubusercontent.com/Pymmdrza/xBrainWallet/mainx/xbrainHeader.png)
# xBrainWallet
## Brain Wallet Passphares and Private Key Crack

Better use `vBrain.py` . needed alphabet word text file on path file.

- Generated Countor Per Scan `Scan`
- Generated and Recorded Total Wallet With Transaction `TX`
- Generated and Recorded Total Wallet With Balance `Rich`

if Needed BigData in Alphabet Words Can order [Here.](https://mmdrza.com)

---

Screen From Working `/xBrain_V3/vBrain.py` with BigData Alphabet Words:

![vBrain.py Brain Wallet Bitcoin Crack PrivateKey](https://github.com/Pymmdrza/xBrainWallet/raw/mainx/vBrain.gif)

---

For Generated Address Wallet in Passphrase used This Code From `vBrain.py`

```python:
    def generate_address_from_passphrase(passphrase) :
        private_key = str(hashlib.sha256(
            passphrase.encode('utf-8')).hexdigest())
        address = BrainWallet.generate_address_from_private_key(private_key)
        return private_key , address

```
for Created Address From Private Key used This Code :

```python:
    @staticmethod
    def generate_address_from_private_key(private_key) :
        public_key = BrainWallet.__private_to_public(private_key)
        address = BrainWallet.__public_to_address(public_key)
        return address
```
Generated address hex on base58 with alphabet words `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` in static method i used this code in `vBrain.py`

```python:
    @staticmethod
    def base58(address_hex) :
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58_string = ''
        leading_zeros = len(address_hex)-len(address_hex.lstrip('0'))
        address_int = int(address_hex , 16)
        while address_int > 0 :
            digit = address_int%58
            digit_char = alphabet[digit]
            b58_string = digit_char+b58_string
            address_int //= 58
        ones = leading_zeros//2
        for one in range(ones) :
            b58_string = '1'+b58_string
        return b58_string
```				

---

![For BrainAllValue_V1.py Bitcoin Wallet Hack](https://raw.githubusercontent.com/Pymmdrza/xBrainWallet/mainx/BrainAllValue.JPG)


first install package's:
```
pip install colorama ecdsa rich
```
for running use this common :
```
python BrainWallet.py
```

---

for use online generetad and crack brain wallet run code:

`python xBrainOn.py`

---

