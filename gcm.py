try:    
    from Crypto.Cipher import AES
    from Crypto.Util import Padding
    from Crypto.Random import get_random_bytes
except ModuleNotFoundError:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Padding
    from Cryptodome.Random import get_random_bytes

import conversions

"""Built-in Cryptodomex GCM encryption and decryption example"""

header = b"header"
data = b"secret"
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_GCM)
cipher.update (header)
ciphertext, tag = cipher.encrypt_and_digest(data)

print (ciphertext, tag)

nonce = cipher.nonce

print(nonce)

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
cipher.update(header)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print(plaintext)
