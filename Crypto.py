import random

def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b

def FindInverse(n2, n1):
    if gcd(n1, n2) != 1:
        raise Exception("GCD of {} and {} aren't equal 1 so it don't have Inverse".format(n1, n2))

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

def power(a, b):
    result = 1
    while b >= 0:
        result = result * a
        b -= 1
    return result

# Lehmann Test
def isPrime(n, t):
    a = random.randint(2, n-1)
    expo = (n-1)//2

    if n % 2 == 0:
        return False

    while t>0:
        result = FastExponential(a,expo,n)

        if result == 1 or result == n-1:
            a = random.randint(2, n-1)
            t -= 1
        else: 
            return False # Not Prime
    return True # Prime

# RSA Key Generator
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

    # if decimal >= 2**(n-1) or decimal <= 2**n:
    if decimal >= power(2, n-1) or decimal <= power(2,n):
        while True:
            if isPrime(decimal, 1000):
                return decimal
            decimal += 1
    else:
        return -1

def getGenerator(alpha, p):
    if isPrime(p, 1000) == False:
        raise Exception('To get generator of Zp P must be Prime')

    if isPrime((p - 1)//2, 1000) == False:
        raise Exception('(p - 1)/2 is Not Safe Prime')

    if FastExponential(alpha, (p - 1)//2, p) != 1:
        return alpha
    else: 
        return -alpha % p

def FindGenerator(p):
    s = set()

    while len(s) <= 2:
        # alpha not equal to +-1 mod p
        alpha = random.randrange(2, p-2)
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

while True:
    print('Please Select')
    print('1.Generate Prime')
    print('2.Find Inverse')
    print('3.Find Generator')
    print('4.Elgamal')
    print('5.Elgamal Encrypt')
    print('6.Elgamal Decrypt')
    print('7.Exit')

    choice = input('Input : ')
    if choice == '1':
        keySize = input('Key Size :')
        file = input('File :')
        g = GenP(int(keySize), file)
        print('Prime is ', g)
    elif choice == '2':
        value = input('Value : ')
        mod = input('Mod With : ')
        inverse = FindInverse(int(value),int(mod))
        print('Inverse of {} % {} is {}'.format(value,mod,inverse))
    elif choice == '3':
        prime = input('Prime Value : ')
        g = FindGenerator(int(prime))
        print('Generator is ', g)
    elif choice == '4':
        # Bob
        plainText = input('Plaintext : ')
        keySize = input('KeySize : ')
        file = input('File to read and gen key : ')
        publicKey, privateKey = ElgamalKeyGenerator(int(keySize),file)
        cipherText, p = ElgamalEncrypt(plainText, publicKey)

        # Alice
        plainText = ElgamalDecrypt(cipherText, privateKey, p)

        print('Public Key', publicKey)
        print('Private Key', privateKey)
        print('Ciphertext', cipherText)
        print('Plaintext', plainText)

        # To String
        decryptString = ""
        for i in range(len(plainText)):
            decryptString += chr(plainText[i])

        print('To String:',decryptString)
    elif choice == '5':
        fname = input('File to encrypt : ')
        f = open(fname, 'rb')
        enc = f.read().decode()
        keySize = input('KeySize : ')
        file = input('File to read and gen key : ')
        publicKey, privateKey = ElgamalKeyGenerator(int(keySize),file)
        f = open(f'{fname}.key', 'w')
        f.write(hex(privateKey)[2:])
        f = open(f'{fname}.pub', 'w')
        f.write(','.join(hex(x)[2:] for x in publicKey))
        cipherText, p = ElgamalEncrypt(enc, publicKey)
        f = open(f'{fname}.enc', 'w')
        a = cipherText[0]
        b = cipherText[1]
        f.write(hex(a)[2:])
        f.write(',')
        f.write(','.join(hex(x)[2:] for x in b))
        f.write(',')
        f.write(hex(p)[2:])
        f.close()
    elif choice == '6':
        privateKeyf = input('Private key file: ')
        cipherTextf = input('Ciphertext file: ')

        f = open(privateKeyf, 'r')
        privateKeyhex = f.read()
        privateKey = int(privateKeyhex, 16)
        f = open(cipherTextf, 'r')
        cipherTextdump = f.read()
        cipherTextlist = cipherTextdump.split(',')
        a = int(cipherTextlist[0], 16)
        b = []
        bdump = cipherTextlist[1:-1]
        for i in bdump:
          b.append(int(i,16))
        p = int(cipherTextlist[-1], 16)
        cipherText = (a, b)

        plainText = ElgamalDecrypt(cipherText, privateKey, p)
        # To String
        decryptString = ""
        for i in range(len(plainText)):
            decryptString += chr(plainText[i])
        newfile = cipherTextf.split('enc')[0]
        f = open(f'{newfile}dec', 'w')
        f.write(decryptString)
        f.close()
    elif choice == '7':
        break
    else:
        continue
