import codecs , random , hashlib , ecdsa , sys , time
from time import sleep
from rich.console import Console
from rich import print
from rich.panel import Panel
from rich.console import Console
from lxml import html
import requests
import threading

console = Console()
console.clear()

filexname = input('INSERT HERE File Name <---------|Without type file .txt|----------> : ')
#
def Bal(address) :
    urlblock = "https://bitcoin.atomicwallet.io/address/"+address
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code = html.fromstring(byte_string)
    xpatch_txid = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
    treetxid = source_code.xpath(xpatch_txid)
    xVol = str(treetxid[0].text_content())
    return xVol


def xBal(address) :
    urlblock = "https://bitcoin.atomicwallet.io/address/"+address
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code = html.fromstring(byte_string)
    xpatch_txid = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    treetxid = source_code.xpath(xpatch_txid)
    xVol = str(treetxid[0].text_content())
    return xVol


mylist = []

filename = str(filexname+".txt")
with open(filename, newline = '' , encoding = 'utf-8') as f :
    for line in f :
        mylist.append(line.strip())


class BrainWallet :

    @staticmethod
    def generate_address_from_passphrase(passphrase) :
        private_key = str(hashlib.sha256(
            passphrase.encode('utf-8')).hexdigest())
        address = BrainWallet.generate_address_from_private_key(private_key)
        return private_key , address

    @staticmethod
    def generate_address_from_private_key(private_key) :
        public_key = BrainWallet.__private_to_public(private_key)
        address = BrainWallet.__public_to_address(public_key)
        return address

    @staticmethod
    def __private_to_public(private_key) :
        private_key_bytes = codecs.decode(private_key , 'hex')
        key = ecdsa.SigningKey.from_string(
            private_key_bytes , curve = ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes , 'hex')
        bitcoin_byte = b'04'
        public_key = bitcoin_byte+key_hex
        return public_key

    @staticmethod
    def __public_to_address(public_key) :
        public_key_bytes = codecs.decode(public_key , 'hex')
        # Run SHA256 for the public key
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest , 'hex')
        network_byte = b'00'
        network_bitcoin_public_key = network_byte+ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(
            network_bitcoin_public_key , 'hex')
        sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest , 'hex')
        checksum = sha256_2_hex[:8]
        address_hex = (network_bitcoin_public_key+checksum).decode('utf-8')
        wallet = BrainWallet.base58(address_hex)
        return wallet

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


def MmDrza() :
    s = 0
    w = 0
    count = 0
    for i in range(0 , len(mylist)) :
        count += 2
        passphrase = mylist[i]
        wallet = BrainWallet()
        private_key , address = wallet.generate_address_from_passphrase(passphrase)
        dec = int(private_key , 16)
        urlblock = "https://bitcoin.atomicwallet.io/address/"+address
        respone_block = requests.get(urlblock)
        byte_string = respone_block.content
        source_code = html.fromstring(byte_string)
        xpatch_txid = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
        treetxid = source_code.xpath(xpatch_txid)
        xVol = str(treetxid[0].text_content())
        bal = str(xVol)
        ifbtc = '0 BTC'
        if int(bal) > 0 :
            urlblock1 = "https://bitcoin.atomicwallet.io/address/"+address
            respone_block1 = requests.get(urlblock1)
            byte_string1 = respone_block1.content
            source_code1 = html.fromstring(byte_string1)
            xpatch_txid1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            treetxid1 = source_code1.xpath(xpatch_txid1)
            xVol1 = str(treetxid1[0].text_content())
            val = str(xVol1)
            MmdrzaPanel = str(
                '[gold1 on grey15]Total Checked: '+'[orange_red1]'+str(count)+'[/][gold1 on grey15] '+' Win:'+'[white]'+str(w)+'[/]'+'[/][gold1]                  TX: '+'[/][aquamarine1]'+str(
                    bal)+'[gold1]  BAL:[aquamarine1]'+str(val)+'\n[/][gold1 on grey15]Addr: '+'[white] '+str(address)+'[gold1 on grey15]                  Passphrase: '+'[orange_red1]'+str(passphrase)+'[/]\nPRIVATEKEY: [grey54]'+str(private_key)+'[/]')
            style = "gold1 on grey11"
            f1 = open(u"vBrain_"+str(filexname)+"_TX.txt" , "a")
            f1.write('\nBitcoin Address Compressed : '+address+'  TX = '+str(bal))
            f1.write('\nPassphrase       : '+passphrase)
            f1.write('\nPrivate Key      : '+private_key)
            f1.write('\nBalance: '+str(val))
            f1.write('\n-------------- Programmer Mmdrza.Com ----------------------\n')
            f1.close()
            console.print(Panel(str(MmdrzaPanel) , title = "[white]Win Wallet [/]" , subtitle = "[green_yellow blink] Mmdrza.Com [/]" , style = "red") , style = style , justify = "full")

            w += 1
            if str(val) != str(ifbtc) :
                s += 1
                MmdrzaB = str(
                    '[green on grey15]Total Checked: '+'[orange_red1]'+str(count)+'[/][gold1 on grey15] '+' Win:'+'[white]'+str(w)+'[/]'+'[/][gold1]                  TX: '+'[/][aquamarine1]'+str(
                        bal)+'[gold1]  BAL:[aquamarine1]'+str(val)+'\n[/][gold1 on grey15]Addr: '+'[white] '+str(address)+'[/]\nPRIVATEKEY: [grey54]'+str(private_key)+'[/]')
                console.print(Panel(str(MmdrzaB) , title = "[white]Win Wallet [/]" , subtitle = "[green_yellow blink] Mmdrza.Com [/]" , style = "green") , style = style , justify = "full")

                f = open(u"vBrain_"+str(filexname)+"_Balance.txt" , "a")
                f.write('\nBitcoin Address Compressed : '+address+'  TX = '+str(bal))
                f.write('\nPassphrase       : '+passphrase)
                f.write('\nPrivate Key      : '+private_key)
                f.write('\nBalance: '+str(val))
                f.write('\n-------------- Programmer Mmdrza.Com ----------------------\n')
                f.close()
        else :
            console.print('[gold1 on grey7]Scan:[light_goldenred1]'+str(count)+'[gold1] Tx:[white]'+str(w)+'[green] Rich:[white]'+str(s)+'[/][yellow] Add:[green1]'+str(address)+'[red1]  TXID:[white]'+str(
                bal)+'[gold1]  Passphars:[white]'+str(passphrase))


thr = threading.Thread(target = MmDrza , args = ())
thr.start()
thr.join()
