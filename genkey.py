from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from base64 import b64decode,b64encode

f = open("rsa.pub","r")

pubkey = f.read()
msg = "test"
# keyDER = b64decode(pubkey)
keyPub = RSA.importKey(pubkey)
cipher = Cipher_PKCS1_v1_5.new(keyPub)
cipher_text = cipher.encrypt(msg.encode())
emsg = b64encode(cipher_text)
print emsg