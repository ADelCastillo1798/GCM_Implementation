try:    
    from Crypto.Cipher import AES
    from Crypto.Util import Padding
    from Crypto.Random import get_random_bytes
except ModuleNotFoundError:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Padding
    from Cryptodome.Random import get_random_bytes

import conversions as c

"""Built-in Cryptodomex GCM encryption and decryption example"""

# header = b"header"
# data = b"secret"
# key = get_random_bytes(16)
# ex_cipher = AES.new(key, AES.MODE_GCM)
# ex_cipher.update (header)
# ciphertext, tag = ex_cipher.encrypt_and_digest(data)

# print (ciphertext, tag)

# nonce = ex_cipher.nonce
# print(nonce)

# ex_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
# ex_cipher.update(header)
# plaintext = ex_cipher.decrypt_and_verify(ciphertext, tag)
# print(plaintext)

def multiply(x: bytes, y: bytes) -> bytes:
    r = b"e1"
    z = b"0"*16
    v = x
    #need r, z and v in binary to traverse all 128 bits properly and perform the below
    for i in range(0,128):
        if y[i] == 1:
            z = c.xor(z,v)
        if v[127] == 0:
            v = v >> 1
        else: 
            v = x.xor((v >> 1), r)
    return z

def crude_gcm(y: bytes, x: bytes) -> (bytes, bytes):
    return