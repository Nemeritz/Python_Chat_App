from itertools import cycle, izip
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import sqlite3

class encDec(object):
    #encrypts and decrypts messages/ciphers
    def endeXOR(message):
        key = "01101001"
        return ''.join(chr(ord(c1)^ord(c2)) for c1,c2 in izip(message,cycle(key)))
    
    def en256(message):
        key = "41fb5b5ae4d57c5ee528adb078ac3b2e"
        mode = AES.MODE_CBC
        IV = 16 * ' '
        encryptor = AES.new(key, mode, IV=IV)
        encrypted_message = encryptor.encrypt(self.padding())
        return encrypted_message
    
    def de256(message):
        key = "41fb5b5ae4d57c5ee528adb078ac3b2e"
        mode = AES.MODE_CBC
        IV = 16 * ' '
        decryptor = AES.new(key, mode, IV=IV)
        decrypted_message = decrypted_message.decrypt(message)
        return decrypted_message

    def padding(s):
        BS = 16
        pad = ' '
        return s + (BS - len(s) % BS) * pad

    def encRSA(message):
        conn = sqlite3.connect('302Database')
        c = conn.cursor()
        c.execute("SELECT Private FROM userKey")
        private = c.fetchone()
        c.close()
        conn.close()
        
        privateKey = RSA.importKey(private)
        publicKey = privateKey
        return publicKey.encrypt(message, 32)

    def decRSA(message):
        conn = sqlite3.connect('302Database')
        c = conn.cursor()
        c.execute("SELECT Private FROM userKey")
        private = c.fetchone()
        c.close()
        conn.close()
        
        privateKey = RSA.importKey(private)
        return privateKey.encrypt(message, 32)
