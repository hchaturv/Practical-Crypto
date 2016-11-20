from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes #AES Encryption
from cryptography.hazmat.primitives.asymmetric import rsa #Generate RSA Keys
from cryptography.hazmat.primitives.asymmetric import dsa #Generate DSA Keys
from cryptography.hazmat.primitives import hashes #Hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import binascii
import base64
import requests
import simplejson as json
import readline
from struct import *

BLOCK_SIZE      = 16
ASCII           = lambda x: x.decode("hex")
CRC32           = lambda x: binascii.crc32(x) & 0xffffffff
UNPAD           = lambda x: x[:-int(x[-1])]
B64ENC          = lambda x: base64.b64encode(x)
B64DEC          = lambda x: base64.b64decode(x)
UTF8ENC         = lambda x: x.encode('utf-8')
UTF8DEC         = lambda x: x.decode('utf-8')
bin_to_int      = lambda x: int(binascii.hexlify(x),16)
J_SERVER       = "http://localhost:80"                      #JMessage Server running on Localhost
HEADER          = {'Accept': 'application/json'}


class jCompleter(object):  # Custom completer
    def __init__(self, options):
        self.options = sorted(options)

    def complete(self, text, state):
        if state == 0:  # on first trigger, build possible matches
            if text:  # cache matches (entries that start with entered text)
                self.matches = [s for s in self.options
                                    if s and s.startswith(text)]
            else:  # no text entered, all matches possible
                self.matches = self.options[:]
        # return match indexed by state
        try:
            return self.matches[state]
        except IndexError:
            return None

class jClient_node:

    def __init__(self):
        self.__my_user_name     = None
        self.__my_rsa_inst_sec  = None
        self.__my_rsa_inst_pub  = None
        self.__my_dsa_inst_sec  = None
        self.__my_dsa_inst_pub  = None
        self.__my_der_sec_rsa   = None
        self.__my_der_pub_rsa   = None
        self.__my_der_sec_dsa   = None
        self.__my_der_pub_dsa   = None
        self.__my_b64_pub_rsa   = None
        self.__my_b64_pub_dsa   = None

    def __init_completer(self,options):
        completer        = jCompleter(options)
        return completer


    def __set_user(self):
        self.__my_user_name = raw_input("Enter a user name: ")

    def __send_message(self,msg_type,path,msg=None):
        resp = None
        if msg_type.lower() == 'get':
            resp    = requests.get(J_SERVER+path, headers=HEADER)
        elif msg_type.lower() == 'post':
            resp    = requests.post(J_SERVER+path, json=msg, headers=HEADER)
        return resp

    def __generate_RSA_keys(self,bits):
        self.__my_rsa_inst_sec   = rsa.generate_private_key(public_exponent=65537,key_size=bits,backend=default_backend())
        self.__my_rsa_inst_pub   = self.__my_rsa_inst_sec.public_key()
        self.__my_der_sec_rsa    = self.__my_rsa_inst_sec.private_bytes(encoding=serialization.Encoding.DER,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())#d
        self.__my_der_pub_rsa    = self.__my_rsa_inst_pub.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)#e
        self.__my_b64_pub_rsa    = base64.b64encode(self.__my_der_pub_rsa)

    def __generate_DSA_keys(self,bits):
        self.__my_dsa_inst_sec   = dsa.generate_private_key(key_size=bits,backend=default_backend())
        self.__my_dsa_inst_pub   = self.__my_dsa_inst_sec.public_key()
        self.__my_der_sec_dsa    = self.__my_dsa_inst_sec.private_bytes(encoding=serialization.Encoding.DER,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())#d
        self.__my_der_pub_dsa    = self.__my_dsa_inst_pub.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)#e
        self.__my_b64_pub_dsa    = base64.b64encode(self.__my_der_pub_dsa)

    def __generate_AES_keys(self, bits):
        return (os.urandom((bits/8)))

    def __generate_IV(self, size):
        return(os.urandom(size))

    def __generate_MSG_ID(self, size):
        val = int(binascii.hexlify(os.urandom(size)),16)
        return val

    def __generate_keys(self,ch, size=None):
        if ch == 'RSA':
            self.__generate_RSA_keys(size)
            return
        elif ch == 'DSA':
            self.__generate_DSA_keys(size)
            return
        elif ch == 'AES':
            return(self.__generate_AES_keys(size))
        elif ch == 'IV':
            return(self.__generate_IV(size))
        elif ch == 'MSG_ID':
            return(self.__generate_MSG_ID(size))

    def __register_keys_msg(self):
        self.__generate_keys('RSA',1024)
        self.__generate_keys('DSA',1024)
        enc_key_data         = self.__my_b64_pub_rsa+ASCII('25')+self.__my_b64_pub_dsa
        enc_key_data_utf8    = UTF8ENC(enc_key_data)
        key_data_json   = {"keyData":enc_key_data_utf8}  # TODO Potential Problem - enc_key_data has to be string based on doc. Receiver parsing might generate errors
        path            = "/registerKey/"+self.__my_user_name
        resp            = self.__send_message('post',path,key_data_json) # TODO Decide what to do with the response
        return resp

    def __get_keys(self,member):
        path            = '/lookupKey/'+member
        user_info_json  = self.__send_message('get',path)
        user_info       = json.loads(user_info_json.text)
        if user_info['status'] != "found key":
            return None
        key_data        = user_info['keyData']
        return key_data

    def __parse_for_keys(self, key_data):
        if key_data[216]!='%':
            print("Error - Keys received from server not formatted properly\n")
            return
        r_pub_rsa_b64          = key_data[:216]
        r_pub_dsa_b64          = key_data[217:]
        r_pub_rsa_der          = B64DEC(r_pub_rsa_b64)
        r_pub_dsa_der          = B64DEC(r_pub_dsa_b64)
        #self.__r_pub_rsa       = serialization.load_der_public_key(self.__r_pub_rsa_der,backend=default_backend())
        #self.__r_pub_dsa       = serialization.load_der_public_key(self.__r_pub_dsa_der,backend=default_backend())
        r_pub_rsa              = serialization.load_der_public_key(r_pub_rsa_der,backend=default_backend())
        r_pub_dsa              = serialization.load_der_public_key(r_pub_dsa_der,backend=default_backend())
        return (r_pub_rsa,r_pub_dsa)

    def __parse_for_sender_keys(self, key_data):
        if key_data[216]!='%':
            print("Error - Keys received from server not formatted properly\n")
            return
        s_pub_rsa_b64   = key_data[:216]
        s_pub_dsa_b64   = key_data[217:]
        s_pub_rsa_der   = B64DEC(s_pub_rsa_b64) # import this
        s_pub_dsa_der   = B64DEC(s_pub_dsa_b64) # import this
        s_pub_rsa       = serialization.load_der_public_key(s_pub_rsa_der,backend=default_backend())
        s_pub_dsa       = serialization.load_der_public_key(s_pub_dsa_der,backend=default_backend())
        return (s_pub_rsa,s_pub_dsa)

    def __printArray(self, arr):
        for i in range (len(arr)):
            print("[%d] %s"%(i,arr[i]))

    def __print_users(self):
        user_base_json      = self.__send_message('get','/lookupUsers')
        user_base           = json.loads(user_base_json.text)
        user_base['users']  = sorted(user_base['users'])
        self.__printArray(user_base['users'])
        return user_base['users']

    def __select_peer(self,name=None):
        if name == None:
            users = self.__print_users()
            print "Double Tab to Autocomplete"
            '''
            Autocomplete - Double press <tab> to get suggestions.
            '''
            autocomp_uname = self.__init_completer(users)
            readline.set_completer(autocomp_uname.complete)
            readline.parse_and_bind('tab: complete')
            member = raw_input("The Other Guy: ")
            '''
            Classic Method:

            while 1:
                idx = (raw_input("Enter user index or Enter -1 to exit: "))
                if idx not in users:
                    print "User not in list"
                    continue
                elif idx == None:
                    return None,None,None
                else:
                    member = idx
                    #print "You have chosen to talk to %s"%member
                    break
            '''
        else:
            member = name

        key_data              = self.__get_keys(member)
        (r_pub_rsa,r_pub_dsa) = self.__parse_for_keys(key_data)
        return (member,r_pub_rsa,r_pub_dsa)

    def __get_user_message(self):
        user_msg = raw_input("Enter Message to Send: ")
        return user_msg

    def __encrypt_message(self, msg, sname,r_pub_rsa, r_pub_dsa):
        eph_key         = self.__generate_keys('AES',128) # Step 1
        c1              = self.__encrypt_msg_pkcs1v1_5(sname, eph_key, r_pub_rsa) # Step 2
        msg_formatted   = self.__my_user_name+ASCII("3A")+msg #Step 3
        msg_crc         = msg_formatted+pack('!L',CRC32(msg_formatted)) # Step 4
        msg_padded      = self.__pad(msg_crc) # Step 5
        iv              = self.__generate_keys('IV',16) # Step 6
        cipher          = Cipher(algorithms.AES(eph_key), modes.CTR(iv), backend=default_backend())
        encryptor       = cipher.encryptor()
        c2_wo_iv        = encryptor.update(msg_padded)+encryptor.finalize()
        c2              = iv+c2_wo_iv # Step 7
        c1_b64          = B64ENC(c1)
        c2_b64          = B64ENC(c2)
        c1_utf8         = UTF8ENC(c1_b64)
        c2_utf8         = UTF8ENC(c2_b64) # Step 8
        utf8_enc_str    = c1_utf8+ASCII('20')+c2_utf8
        dsa_signature   = UTF8ENC(B64ENC(self.__sign_msg(utf8_enc_str))) # Step 9 & Step 10
        c               = utf8_enc_str+ASCII('20')+dsa_signature # Step 11
        return c

    def __pad(self, msg):
        mod          = len(msg)%16
        if mod > 0:
            modp     = hex(16-mod)[2:]
            if(len(modp)%2 != 0):
                modp = "0"+modp
            padding  = modp*(16-mod)
        else:
            padding  = "10"*16
        pad_str = msg+binascii.unhexlify(padding)
        return pad_str


    def __encrypt_msg_pkcs1v1_5(self,sname, eph_key, r_pub_rsa):
        ciphertext            = r_pub_rsa.encrypt(eph_key, padding.PKCS1v15())
        return ciphertext

    def __sign_msg(self,msg):
        signer      = self.__my_dsa_inst_sec.signer(hashes.SHA1())
        signer.update(msg)
        return (signer.finalize())

    def __send_encrypted_msg(self, c, sname):
        msg_id          = self.__generate_keys('MSG_ID',2)
        enc_json        = {"recipient": sname, "messageID": msg_id, "message": c}
        path            = "/sendMessage/"+self.__my_user_name
        self.__send_message('post',path,enc_json)

    def __message_poll(self, mname): # Get others' messages by adding custom sname value
        path        = "/getMessages/"+mname
        msgs_json   = json.loads((self.__send_message("get",path)).text)
        total       = msgs_json['numMessages']
        msgs        = msgs_json['messages']
        if total==0:
            print "No messages to read at this time"
        else:
            for i in range (total):
                print "Message from %s was received at time: %s" %(msgs[i]['senderID'],msgs[i]['sentTime'])
                self.__decrypt_message(msgs[i]['message'], msgs[i]['messageID'], msgs[i]['senderID'])
                print "\n"

    def __decrypt_message(self, ctext, msg_id, sname):
        key_data                        = self.__get_keys(sname)  #  Step 1 Message can be from anyone. You need to get keys
        s_pub_rsa,s_pub_dsa             = self.__parse_for_sender_keys(UTF8DEC(key_data))
        (authentic,c1,c2)               = self.__parse_verify_ctext(str(ctext),s_pub_dsa,s_pub_rsa) #  Step 2,3,4
        if authentic != True:
            return
        eph_key                         = self.__decrypt_msg_pkcs1v1_5(c1)
        iv,c2_wo_iv                     = self.__extract_iv(c2)
        cipher                          = Cipher(algorithms.AES(eph_key), modes.CTR(iv), backend=default_backend())
        decryptor                       = cipher.decryptor()
        msg_padded                      = decryptor.update(c2_wo_iv)+decryptor.finalize()
        (padding_verify,msg_crc)        = self.__verify_padding(msg_padded)
        if padding_verify != True:
            return
        (crc_verify,msg_formatted)      = self.__verify_crc(msg_crc)
        if crc_verify != True:
            return
        (sender_verify,msg)             = self.__verify_sender(sname, msg_formatted)
        if sender_verify != True:
            return
        if not self.__isReadReceipt(msg):
            self.__send_read_receipt(sname,msg_id,s_pub_dsa,s_pub_rsa)
        self.__display_message(sname, msg)

    def __decode_base64(self, ctext_wo_sign):
        if ctext_wo_sign[172] != ASCII('20'):
            return
        utf8_c1         = ctext_wo_sign[:172]
        utf8_c2         = ctext_wo_sign[173:]
        c1_b64          = UTF8DEC(utf8_c1)
        c2_b64          = UTF8DEC(utf8_c2)
        c1              = B64DEC(c1_b64)
        c2              = B64DEC(c2_b64)
        return c1,c2

    def __extract_signature(self,ctext):
        return ctext[-64:],ctext[:-65]

    def __verify_signature(self,ctext_utf8,s_pub_dsa):
        ctext                       = ctext_utf8
        signature_b64,ctext_wo_sign = self.__extract_signature(ctext)
        signature                   = B64DEC(signature_b64)
        verifier                    = s_pub_dsa.verifier(signature, hashes.SHA1())
        verifier.update(ctext_wo_sign)
        try:
            verifier.verify()
        except:
            return False, ctext_wo_sign
        return True,ctext_wo_sign

    def __parse_verify_ctext(self, ctext,s_pub_dsa,s_pub_rsa):
        authentic,ctext_wo_sign     = self.__verify_signature(ctext,s_pub_dsa) #
        if authentic == False:
            return False,None,None
        else:
            c1,c2                  = self.__decode_base64(ctext_wo_sign) #
        return authentic,c1,c2

    def __decrypt_msg_pkcs1v1_5(self, c1):
        ciphertext  =   self.__my_rsa_inst_sec.decrypt(c1, padding.PKCS1v15())
        return ciphertext

    def __extract_iv(self, ctext):
        iv          = ctext[:16]
        ctext_wo_iv = ctext[16:]
        return iv,ctext_wo_iv

    def __verify_padding(self, pad_msg):
        last_byte = pad_msg[-1]
        i = len(pad_msg)-(bin_to_int(last_byte))
        while i< len(pad_msg):
            if pad_msg[i] != last_byte:
                return False, None
            i+=1
        return True,pad_msg[:-(bin_to_int(last_byte))]

    def __verify_crc(self, msg_crc):
        crc,= unpack('!L',msg_crc[-4:])
        msg= msg_crc[:-4]
        if CRC32(msg) != crc:
            return False,None
        else:
            return True,msg

    def __verify_sender(self, sname,msg_formatted):
        for i in range(len(msg_formatted)):
            if msg_formatted[i] == ASCII('3A'):
                sender  = msg_formatted[:i]
                msg     = msg_formatted[i+1:]
                if sender != sname:
                    return False,None
                else:
                    return True,msg
        return False,None

    def __isReadReceipt(self, msg):
        #print "In read receipt: "%msg
        if msg[:14] == '>>>READMESSAGE':
            return True
        else:
            return False

    def __send_read_receipt(self, uname,msg_id,s_pub_dsa,s_pub_rsa):
        user_msg = ">>>READMESSAGE "+str(msg_id)
        self.new_message(uname,user_msg,s_pub_dsa,s_pub_rsa)

    def __display_message(self, sname, msg):
        #print "sname is " %sname
        #print "msg is " %msg
        print "%s - %s" %(sname, msg)

    def __get_fingerprint(self,sname):
        key_data              = self.__get_keys(sname)
        digest                = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(UTF8ENC(key_data))
        pub_key_hex           = binascii.hexlify(digest.finalize())
        print pub_key_hex

    def set_user_name(self):
        self.__set_user()

    def get_user_list(self):
        self.__print_users()
        return

    def new_message(self,peer=None,user_msg=None,r_pub_dsa=None,r_pub_rsa=None):
        if peer == None:
            (peer,r_pub_rsa,r_pub_dsa)  = self.__select_peer() # Get peer
        if peer != None:
            if user_msg == None:
                user_msg                    = self.__get_user_message() # Get message to send
            c                           = self.__encrypt_message(user_msg, peer,r_pub_rsa, r_pub_dsa) # Encrypted message
            self.__send_encrypted_msg(c,peer)
        else:
            return

    def read_messages(self):
        self.__message_poll(self.__my_user_name)
        return

    def register_new_keys(self):
        self.__register_keys_msg()
        print "New pair of public keys registered with the Server"
        return

    def fingerprint(self):
        (peer,r_pub_rsa,r_pub_dsa)  = self.__select_peer() # Get peer
        print "Your fingerprint"
        self.__get_fingerprint(self.__my_user_name)
        print "\n%s's fingerprint"%peer
        self.__get_fingerprint(peer)
        return

    def begin(self):
        self.set_user_name()
        self.register_new_keys()
        print " Welcome %s, You're now registered with the JMessage server. Please choose from the following options: \n(g)et \n(c)ompose, \n(f)ingerprint, \n(l)ist, \n(gen)erate new keys, \n(h)elp, \n(q)uit \n" %self.__my_user_name
        while 1:
            ch = raw_input("Enter choice: ")
            if ch == 'g':
                self.read_messages()
            elif ch == 'c':
                self.new_message()
            elif ch == 'f':
                self.fingerprint()
            elif ch == 'l':
                self.get_user_list()
            elif ch == 'gen':
                self.register_new_keys()
            elif ch == 'h':
                print "Enter choice,: \n(g)et \n(c)ompose, \n(f)ingerprint, \n(l)ist, \n(gen)erate new keys, \n(h)elp, \n(q)uit \n"
            elif ch == 'q':
                break

try:
    obj = jClient_node()
    obj.begin()
except:
    print "Exception Raised"
    pass
