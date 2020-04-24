import random
from math import sqrt 

def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b

def FindInverse(n2, n1):
    tempMod = n1
    r, q = (n1 % n2, n1 // n2)
    a1, b1, a2, b2 = (1, 0, 0, 1)
    while r != 0:
        tempA2 = a2
        tempB2 = b2
        a2 = a1 - q * a2
        b2 = b1 - q * b2
        a1, b1 = tempA2, tempB2
        n1, n2 = n2, r
        r, q = (n1 % n2, n1 // n2)
    if n2 != 1 :
        return "GCD not equal 1"
    return b2 % tempMod

# FastExponential
def FastExponential(base, expo, mod):
    result = 1
    if 1 & expo:
        result = base  
    while expo:
        expo = expo >> 1
        base = (base * base) % mod
        if expo & 1:
            result = (base * result) % mod
    return result

# Lehmann Test
def isPrime(n, t):
    a = random.randint(2, n-1)
    expo = (n-1)//2

    while t>0:
        result = FastExponential(a,expo,n)

        if result == 1 or result == n-1:
            a = random.randint(2, n-1)
            t -= 1
        else: 
            return False # Not Prime
    return True # Prime

def generateLargePrime(keysize):
    while True:
        num = random.randrange(2**(keysize-1),2**(keysize))
        if isPrime(num, 1000):
            return num

def generateKey(keysize):
    p = generateLargePrime(keysize)
    q = generateLargePrime(keysize)
    n = p * q
    m = (p-1)*(q-1)

    while True:
        e = random.randrange(2**(keysize - 1), 2**(keysize))
        if gcd(e, m) == 1:
            break
    
    d = FindInverse(e, m)
    publicKey = (n, e)
    privateKey = (n, d)
   
    return (publicKey, privateKey)

# publicKey, privateKey = generateKey(100)
# print("generate publicKey ", publicKey)
# print("generate privateKey ", privateKey)

def GenP(n, file):
    f = open(file, "rb")
    byte = f.read()
    readByte = n // 8

    skipZero = 0
    while byte[skipZero] == 0:
        skipZero += 1
    i = skipZero

    bitString = ''.join(format(i, '08b') for i in byte[skipZero:(skipZero+readByte+2)])

    startPos = 0
    for i in range(0, len(bitString)): 
        if bitString[i] == '1': 
            startPos = i + 1
            break

    bitString = bitString[(startPos - 1):n + (startPos - 1)]
    decimal = int(bitString, 2)

    if decimal >= 2**(n-1) or decimal <= 2**n:
        while True:
            if isPrime(decimal, 1000):
                return decimal
            decimal += 1
    else:
        return -1

def getGenerator(alpha, p):
    if isPrime(p, 1000) == False:
        return -1
    
    if FastExponential(alpha, (p - 1)//2, p) != 1:
        return alpha
    else: 
        return -alpha % p

def FindGenerator(p):
    s = set()

    while len(s) <= 2:
        alpha = random.randrange(2, p-1)
        g = getGenerator(alpha, p)
        s.add(g)
    
    return s

def GenG(p):
    alpha = random.randrange(2, p-1)
    g = getGenerator(alpha, p)
    return g


# Elgamal Algorithm
def GenKey(p):
    key = random.randrange(1,p-1)
    while gcd(key, p-1) != 1:
        key = random.randrange(1,p-1)
    return key

def ElgamalKeyGenerator(keySize, file):
    p = GenP(keySize ,file)
    g = GenG(p)
    u = random.randrange(1, p)
    y = FastExponential(g,u,p)
    publicKey = (p, g, y)
    privateKey = u
    return (publicKey, privateKey)

def ElgamalEncrypt(plainText, publicKey):
    p, g, y = publicKey
    b = []
    print("Generate Key...")
    k = GenKey(p)
    a = FastExponential(g,k,p)
    partB = FastExponential(y,k,p)

    for i in range(len(plainText)):
        b.append((partB * ord(plainText[i])) % p)
    # b = (FastExponential(y,k,p) * plainText) % p
    return (a, b), p

def ElgamalDecrypt(cipherText, privateKey, p):
    a, b = cipherText
    x = []
    for i in range(0, len(b)):
        x.append(b[i] * FindInverse(FastExponential(a,privateKey,p), p) % p)
    # x = b * FindInverse(FastExponential(a,privateKey,p), p) % p
    return x

# Bob
plainText = "Hello How Are You"

publicKey, privateKey = ElgamalKeyGenerator(120,"original.txt")
cipherText, p = ElgamalEncrypt(plainText, publicKey)

# Alice
plainText = ElgamalDecrypt(cipherText, privateKey, p)

print('Public Key', publicKey)
print('Private Key', privateKey)
print('Ciphertext',cipherText)
print('Plaintext',plainText)

# To String
decryptString = ""
for i in range(len(plainText)):
    decryptString += chr(plainText[i])

print('To String:',decryptString)