#A toolbox for converting between different representations of
#sequences of bytes.  The schemes are

# Python bytes objects---these resemble ASCII strings, but can be used to handle
#arbitrary binary data.  A constant bytestring might be represented by something
#like

#   b'hello'

# in a case where all the characters are printable, or as
#   b'he\xf2\xf3o'
# when only some are. You can access the byte at a given position directly, using
# s[j].

#Hex strings.  These are Python strings over the alphabet
# 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f  Each byte is represented by two characters.
#we'll call this hex

#Base 64 encodings.  These are Python strings over the 64-character alphabet
#consisting of letters, digits, and two additional punctuation symbols. Each
#character represents 6 bits.  Extra alignment characters are appended in case
#the number of bits in the byte sequence is not a multiple of 6. We'll call this
#b64.

#Python lists of ints in the range 0 to 255.  

#The conversion routines have names like bytes_to_b64, hex_to_list, etc.

#Note that the argument has to be a bytes object and not a string when the first word
#of the function name is 'bytes'---if you want to convert a Python ASCII
#string then you have to first call the string_to_bytes method below.
import binascii

#

def bytes_to_list(bytesrep):
    return list(bytesrep)

def list_to_bytes(lisrep):
    return bytes(lisrep)

def list_to_hex(lisrep):
     
    return list_to_bytes(lisrep).hex()
     

def hex_to_list(hexrep):
    pairs=[hexrep[2*i:2*(i+1)] for i in range(len(hexrep)//2)]
    return [int(x,16) for x in pairs]
     

def bytes_to_b64(asrep):
    b64rep=binascii.b2a_base64(asrep)
    #you need to cut off the newline character at the end!
    return(b64rep.decode()[:-1])

def b64_to_bytes(b64rep):
    return  binascii.a2b_base64(b64rep)

#We'll get the other conversions by composition
def bytes_to_hex(asrep):
    return list_to_hex(bytes_to_list(asrep))

def hex_to_bytes(hexrep):
    return list_to_bytes(hex_to_list(hexrep))

def list_to_b64(lisrep):
    return bytes_to_b64(list_to_bytes(lisrep))

def b64_to_list(b64rep):
    return bytes_to_list(b64_to_bytes(b64rep))

def hex_to_b64(hexrep):
    return bytes_to_b64(hex_to_bytes(hexrep))

def b64_to_hex(b64rep):
    return bytes_to_hex(b64_to_bytes(b64rep))

#convert between python bytes objects and ordinary strings

#You'll get an error here if the binary data cannot be represented as an ASCII string
def bytes_to_string(asrep):
    return asrep.decode()



def string_to_bytes(asrep):
    return bytes(asrep,'ascii')

#Added two new functions
def bytes_to_int(by):
    li=bytes_to_list(by)
    val=0
    for j in li:
        val=256*val+j
    return val

def int_to_bytes(int_val):
    li=[]
    while int_val != 0:
        li = [int_val%256]+li
        int_val=int_val//256
    return list_to_bytes(li)

#xor is our basic operation.  This function computes the xor of two bytes objects
#in the native representation.  If the two strings have different lengths
#then the additional bytes of the longer string are not used, and the length
#of the result is the minimum of the lengths of the two starting strings.

def xor(s1,s2):
    le=min(len(s1),len(s2))
    l1=bytes_to_list(s1)
    l2=bytes_to_list(s2)
    return list_to_bytes([l1[j]^l2[j] for j in range(le)])
    



    
    
