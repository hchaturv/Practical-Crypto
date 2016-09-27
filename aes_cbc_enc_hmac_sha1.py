from Crypto.Hash import SHA
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import argparse
import os
import binascii
import hashlib
import hmac
MAX_SIZE = 1024*1024
def sanitize_hex(x):
    if x[0:2] == '0x' or x[0:2] == '0X':
        x = x[2:]
    if x[-1] == 'L':
        x = x[:-1]
    if len(x)%2 !=0:
        x = '0'+x
    return x

def hexify(x):
    h = sanitize_hex(hex(x))
    if len(h)%2 !=0:
        t = "0"+h
        return t
    else:
        return h


xor = lambda x,y: x ^ y
intify_hex = lambda x : int(x,16)
bin_to_int = lambda x : int(binascii.hexlify(x),16)
int_to_bin = lambda x : binascii.unhexlify(hexify(x))
class Crypt:

    mode = None  
    key = None # 32 byte key in HEX
    infile = None
    outfile = None

    def hmac(self, text):
        key_hmac = self.key[:32]
        key_hmac = key_hmac+("0"*96)
        key_hmac = intify_hex(key_hmac)
        ipad = intify_hex("36" *64)
        opad = intify_hex("5C" *64)
	digest_step1 = hexify(xor(key_hmac,ipad))
        digest_step2 = digest_step1.decode("hex") + text.decode("hex")
	sha_digest1 = SHA.new(digest_step2).hexdigest() # returns hex
        digest_step3 = hexify(xor(key_hmac,opad))
        digest_step4 = digest_step3+sha_digest1
        sha_digest2 = SHA.new(binascii.unhexlify(digest_step4)).hexdigest()
        return sha_digest2

    def hmac_auth(self, dec_final):
        dec_final_bin = binascii.unhexlify(dec_final)
        last_byte = dec_final_bin[-1]

        i = len(dec_final_bin)-(bin_to_int(last_byte))
        while i< len(dec_final_bin):
            if dec_final_bin[i] != last_byte:
                print "INVALID PADDING"
                return
            i+=1
        print "VALID PADDING"
        hash_wo_pad = dec_final_bin[:-(bin_to_int(last_byte))]
        msg_wo_tag  = hash_wo_pad[:-20]
        tag         = hash_wo_pad[-20:]
        msg_wo_tag_hex= binascii.hexlify(msg_wo_tag)
        digest  = self.hmac(msg_wo_tag_hex)
        tag_hex = binascii.hexlify(tag)
        if tag_hex == digest:
            print "Decrypted message: %s" %msg_wo_tag_hex
            return "success",msg_wo_tag_hex
        else:
            return "failure"

    
    def aes_decrypt(self,iv,data_blk, decryptor):
        interim_data_bin = decryptor.decrypt(data_blk)
        aes_ecb_dec = strxor(iv,interim_data_bin)
        temp = sanitize_hex(binascii.hexlify(aes_ecb_dec))
        return temp
    
 
    def aes_cbc_dec(self, iv, c_t):
        dec_key   = self.key[32:]
        decryptor = AES.new(binascii.unhexlify(dec_key), AES.MODE_ECB)
        i = 16
        dec_final = self.aes_decrypt(binascii.unhexlify(iv),c_t[0:16],decryptor)
        interim_ctext = c_t[0:16]
        while i+16 <= len(c_t):
            dec_final += self.aes_decrypt(interim_ctext,c_t[i:i+16],decryptor)
            interim_ctext = c_t[i:i+16]
            i +=16
            
        print "Final decrypted block: %s" %dec_final
        return dec_final


    def decrypt(self):
        with open(self.infile,"r") as file_in:
            enc_text = file_in.read()
        iv = enc_text[:32]
        cipher_text = binascii.unhexlify(enc_text[32:])
        dec_final = self.aes_cbc_dec(iv,cipher_text)
        res,dec_msg = self.hmac_auth(dec_final)
        if res == "success":
            print "Successfully decrypted and authenticated"
            with open(self.outfile, "w+") as f:
                f.write(dec_msg)
        else:
            print "Decryption failed or could not authenticate"
        return


    def aes_encrypt(self,iv, data_blk, encryptor):
        interim_data = strxor(iv,data_blk)
        aes_ecb_enc  = encryptor.encrypt(interim_data) # this will return binary data
        return aes_ecb_enc # this is in binary


    def aes_cbc_enc(self, pad_str):
        enc_final = None
        iv_rand = os.urandom(16)
	iv_rand_hex = binascii.hexlify(iv_rand)
	enc_key = self.key[32:] # Key in hex
        enc_key = binascii.unhexlify(enc_key) # Changed key to bin
        encryptor = AES.new(enc_key, AES.MODE_ECB)
        i =32

        interim_ctext = self.aes_encrypt(iv_rand,binascii.unhexlify(pad_str[0:32]),encryptor)
        enc_final     = interim_ctext

        while i+32 <= len(pad_str):
            interim_ctext = self.aes_encrypt(interim_ctext,binascii.unhexlify(pad_str[i:i+32]),encryptor)
            enc_final    += interim_ctext
            i+=32

        return iv_rand_hex+binascii.hexlify(enc_final)

    def encrypt(self):
        pad_str   = None
        with open(self.infile, "r") as file_in:
            text      = file_in.read() # Raw binary text 
            if text[-1:] == '\n':
                text = text[:-1]

        if(len(text)%2!=0):
            text = "0"+text
        hash_tag = self.hmac(text)
        text_hash = text+hash_tag
        mod = (len(text_hash)/2)%16
        if mod > 0:
            modp    = hex(16-mod)[2:]
            if(len(modp)%2 != 0):
                modp = "0"+modp
            padding = modp*(16-mod)
        else:
            padding = "10"*16

        padded_str = text_hash+padding
        encrypted_data = self.aes_cbc_enc(padded_str) #in hex
        with open(self.outfile, 'w+') as f:
            f.write(encrypted_data)
        print "Final Encrypted Block : %s" %encrypted_data
	return

    def argparse(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("mode", help="this is the mode you are running the program in , encrypt/decrypt")
        parser.add_argument("-k", help="this would be followed by a 32 byte key in HEX, 1st 16 bytes used for HMAC and next 16 for encryption")
        parser.add_argument("-i", help ="this is the input file with the text to be encrypted or decrypted")
        parser.add_argument("-o", help="this is the output file which will have the encrypted/decrypted text dumped into it")
        args = parser.parse_args()
        if args.k[:2] == "0x" or args.k[:2] == "0X":
            self.key = args.k[2:]
        else:
            self.key = args.k

        if len(self.key)!=64:
            return
        
        self.infile = args.i
        self.outfile = args.o
        if os.path.getsize(self.infile) > MAX_SIZE:
            print "File size is > 1MB"
            return
        if args.mode == "encrypt":
           self.encrypt() 
        elif args.mode == "decrypt":
           self.decrypt()
        else:
            print "Error: Unknown mode entered"
            return 
        return


obj = Crypt()
obj.argparse()	
