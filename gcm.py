try:    
    from Crypto.Cipher import AES
    from Crypto.Util import Padding
    from Crypto.Util import Counter
    from Crypto.Random import get_random_bytes
    from Crypto.Util.number import bytes_to_long, long_to_bytes
except ModuleNotFoundError:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Padding
    from Crypto.Util import Counter
    from Cryptodome.Random import get_random_bytes
    from Crypto.Util.number import bytes_to_long, long_to_bytes

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

pretable = []
def multiply(x: bytes, y: bytes) -> bytes:
    r = b"e1"
    z = b"0"*16
    v = x
    #need r, z and v in binary to traverse all 128 bits properly and perform the below
    for i in range(0,128):
        if y[i] == 1:
            z ^= v
        if v[127] == 0:
            v = v >> 1
        else: 
            v = x.xor((v >> 1), r)
    return z

def gf_2_128_mul(x, y):
    assert x < (1 << 128)
    assert y < (1 << 128)
    res = 0
    for i in range(127, -1, -1):
        res ^= x * ((y >> i) & 1)  # branchless
        x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
    assert res < 1 << 128
    return res

def change_key(key):
        if key >= (1 << 128):
            print('key should be 128-bit')

        key = long_to_bytes(key, 16)
        aes_ecb = AES.new(key, AES.MODE_ECB)
        auth_key = bytes_to_long(aes_ecb.encrypt(b'\x00' * 16))

        # precompute the table for multiplication in finite field
        for i in range(16):
            row = []
            for j in range(256):
                row.append(gf_2_128_mul(auth_key, j << (8 * i)))
            pretable.append(tuple(row))

key = 0xfeffe9928665731c6d6a8f9467308308
key = long_to_bytes(key, 16)
sample = long_to_bytes(1 << (8 * 1))
aes_ecb = AES.new(key, AES.MODE_ECB)
auth_key = (aes_ecb.encrypt(b'\x00' * 16))
#print(gf_2_128_mul(auth_key, (1 << (8 * 1))))
#print(multiply(auth_key, sample))
x = b'111011'
print((sample[2]))
        
def times_auth_key(val):
        res = 0
        #table = tuple(pretable)
        for i in range(16):
            res ^= pretable[i][val & 0xFF]
            val >>= 8
        return res

def ghash(aad, txt):
        len_aad = len(aad)
        len_txt = len(txt)

        # padding
        if 0 == len_aad % 16:
            data = aad
        else:
            data = aad + b'\x00' * (16 - len_aad % 16)
        if 0 == len_txt % 16:
            data += txt
        else:
            data += txt + b'\x00' * (16 - len_txt % 16)

        tag = 0
        assert len(data) % 16 == 0
        for i in range(len(data) // 16):
            tag ^= bytes_to_long(data[i * 16: (i + 1) * 16])
            tag = times_auth_key(tag)
            # print 'X\t', hex(tag)
        tag ^= ((8 * len_aad) << 64) | (8 * len_txt)
        tag = times_auth_key(tag)

        return tag
    
def encrypt(key, iv, plaintext, auth_data=b''):

        len_plaintext = len(plaintext)
        # len_auth_data = len(auth_data)

        if len_plaintext > 0:
            counter = Counter.new(
                nbits=32,
                prefix=long_to_bytes(iv, 12),
                initial_value=2,  # notice this
                allow_wraparound=False)
            aes_ctr = AES.new(key, AES.MODE_CTR, counter=counter)

            if 0 != len_plaintext % 16:
                padded_plaintext = plaintext + \
                    b'\x00' * (16 - len_plaintext % 16)
            else:
                padded_plaintext = plaintext
            ciphertext = aes_ctr.encrypt(padded_plaintext)[:len_plaintext]

        else:
            ciphertext = b''

        auth_tag = ghash(auth_data, ciphertext)
        # print 'GHASH\t', hex(auth_tag)
        temp = AES.new(key, AES.MODE_ECB)
        auth_tag ^= bytes_to_long(temp.encrypt(
                                  long_to_bytes((iv << 32) | 1, 16)))

        # assert len(ciphertext) == len(plaintext)
        assert auth_tag < (1 << 128)
        return ciphertext, auth_tag
    
def decrypt(key, iv, ciphertext, auth_tag, auth_data=b''):
    aes_ecb = AES.new(key, AES.MODE_ECB)

    if auth_tag != ghash(auth_data, ciphertext) ^ \
            bytes_to_long(aes_ecb.encrypt(
            long_to_bytes((iv << 32) | 1, 16))):
        print('The authenticaiton tag is invalid')

        len_ciphertext = len(ciphertext)
        if len_ciphertext > 0:
            counter = Counter.new(
                nbits=32,
                prefix=long_to_bytes(iv, 12),
                initial_value=2,
                allow_wraparound=True)
            aes_ctr = AES.new(key, AES.MODE_CTR, counter=counter)

            if 0 != len_ciphertext % 16:
                padded_ciphertext = ciphertext + \
                    b'\x00' * (16 - len_ciphertext % 16)
            else:
                padded_ciphertext = ciphertext
            plaintext = aes_ctr.decrypt(padded_ciphertext)[:len_ciphertext]

        else:
            plaintext = b''

        return plaintext

master_key = 0xfeffe9928665731c6d6a8f9467308308
plaintext = b'\xd9\x31\x32\x25\xf8\x84\x06\xe5' + \
                b'\xa5\x59\x09\xc5\xaf\xf5\x26\x9a' + \
                b'\x86\xa7\xa9\x53\x15\x34\xf7\xda' + \
                b'\x2e\x4c\x30\x3d\x8a\x31\x8a\x72' + \
                b'\x1c\x3c\x0c\x95\x95\x68\x09\x53' + \
                b'\x2f\xcf\x0e\x24\x49\xa6\xb5\x25' + \
                b'\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57' + \
                b'\xba\x63\x7b\x39'
auth_data = b'\xfe\xed\xfa\xce\xde\xad\xbe\xef' + \
                b'\xfe\xed\xfa\xce\xde\xad\xbe\xef' + \
                b'\xab\xad\xda\xd2'
init_value = 0xcafebabefacedbaddecaf888
ciphertext = b'\x42\x83\x1e\xc2\x21\x77\x74\x24' + \
                 b'\x4b\x72\x21\xb7\x84\xd0\xd4\x9c' + \
                 b'\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0' + \
                 b'\x35\xc1\x7e\x23\x29\xac\xa1\x2e' + \
                 b'\x21\xd5\x14\xb2\x54\x66\x93\x1c' + \
                 b'\x7d\x8f\x6a\x5a\xac\x84\xaa\x05' + \
                 b'\x1b\xa3\x0b\x39\x6a\x0a\xac\x97' + \
                 b'\x3d\x58\xe0\x91'
auth_tag = 0x5bc94fbc3221a5db94fae95ae7121a47

print('plaintext:', hex(bytes_to_long(plaintext)))
change_key(master_key)
master_key = long_to_bytes(master_key, 16)
encrypted, new_tag = encrypt(master_key, init_value, plaintext, auth_data)
print('encrypted:', hex(bytes_to_long(encrypted)))
print('auth tag: ', hex(new_tag))


decrypted = decrypt(master_key, init_value, encrypted,
                new_tag + 1, auth_data)
#except InvalidTagException:
        #decrypted = decrypt(master_key,init_value, encrypted, new_tag, auth_data)
print('decrypted:', hex(bytes_to_long(decrypted)))

# GF(2^128) defined by 1 + a + a^2 + a^7 + a^128
# Please note the MSB is x0 and LSB is x127
