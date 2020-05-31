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

    if isPrime((p - 1)//2, 1000) == True:
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
    # partB = p.bit_length() - 1
    print('p value', p, 'bit length', p.bit_length() - 1)

    for i in range(len(plainText)):
        # b.append((partB * ord(plainText[i])))
        b.append((partB * ord(plainText[i])) % p)
    # b = (FastExponential(y,k,p) * plainText) % p
    return (a, b), p

def ElgamalEncryptFile(file, publicKey):
    p, g, y = publicKey
    k = GenKey(p)
    a = FastExponential(g,k,p)
    partB = FastExponential(y,k,p)
    blockSize = p.bit_length() - 1
    b = []

    f = open(f'{file}', 'rb')
    byteMessage = f.read()
    bitString = ''.join(format(i, f'0{blockSize}b') for i in byteMessage)
    # bitBlock = [bitString[i:i+blockSize] for i in range(0, len(bitString), blockSize)]
    bitBlock = [int(bitString[i:i+blockSize], 2) for i in range(0, len(bitString), blockSize)]

    for i in range(len(bitBlock)):
        b.append((partB * bitBlock[i]) % p)

    # byteMessage = bytearray([int(bitString[i:i+8], 2) for i in range(0, len(bitString), 8)])
    # cipherBitString = ''.join(format(b[i],'08b') for i in range(len(b)))
    # byte_arr = [int(cipherBitString[i:i+8], 2) for i in range(0, len(cipherBitString), 8)]
    extension = file.split(".")[-1]
    name = file.split(".")[0]
    f = open(f'{name}.encrypt.{extension}', 'w')
    f.write(hex(a)[2:])
    f.write(',')
    f.write(hex(p)[2:])
    f.write(',')
    f.write(','.join(hex(b[i])[2:] for i in range(len(b))))
    f.close()

def ElgamalDecryptFile(file, privateKey):
    privateKey = int(privateKey, 16)
    f = open(f'{file}', 'rb')
    byteMessage = f.read().decode().split(",")
    # print(byteMessage)

    a = int(byteMessage[0],16)
    p = int(byteMessage[1],16)
    b = byteMessage[2:]
    # print('a',a,'b',b)
    x = []
    for i in range(len(b)):
        x.append(int(b[i], 16)*FindInverse(FastExponential(a,privateKey,p), p) % p)

    binaryMessage = ''.join(format(x[i], '08b') for i in range(len(x)))
    byteMessage = bytearray([int(binaryMessage[i:i+8], 2) for i in range(0, len(binaryMessage), 8)])
    extension = file.split(".")[-1]
    name = file.split(".")[0]
    f = open(f'{name}.decrypt.{extension}','wb')
    f.write(byteMessage)
    f.close()

def ElgamalDecrypt(cipherText, privateKey, p):
    a, b = cipherText
    x = []
    for i in range(0, len(b)):
        x.append(b[i] * FindInverse(FastExponential(a,privateKey,p), p) % p)
    # x = b * FindInverse(FastExponential(a,privateKey,p), p) % p
    return x

def isBinary(string):
    p = set(string) 
    s = {'0', '1'}  
    if s == p or p == {'0'} or p == {'1'}: 
        return True
    else : 
        return False

def RWHash(k,p,M):
    if isBinary(M):
        message = M
        alpha = len(M)
    else:
        message = ''.join(format(ord(x), '08b') for x in M)
        alpha = len(message)
    # p = p.bit_length()
    blockString = []
    index = 0
    while len(message) > 0:
        blockString.append(message[:p])
        message = message[p:]
        if len(blockString[index]) != p:
            while len(blockString[index]) != p:
                blockString[index] += blockString[index][-1]
        index += 1

    # HASH
    isFirstRound = True
    hashBlock = []
    l = 0
    while len(blockString) > 0:
        block = blockString[:k-1]
        binaryBlock = ''.join(block)
        if isFirstRound:
            binaryBlock = format(alpha, 'b') + binaryBlock
            subHashValue = int(binaryBlock, 2) % p
            hashBlock.append(subHashValue)
            isFirstRound = False
        else:
            binaryBlock = format(hashBlock[l - 1], 'b') + binaryBlock
            subHashValue = int(binaryBlock, 2) % p
            hashBlock.append(subHashValue)
        
        blockString = blockString[k-1:]
        l += 1

    # Find HASH VALUE!!!
    hashValue = (sum(hashBlock[:-1]) + power(hashBlock[-1],2)) % p
    # print(hex(hashValue))
    return hashValue

def signMessage(signFile, privateKey, publicParameters): 
    p, g, _ = publicParameters
    x = privateKey
    b = []
    k = GenKey(p)
    # k = 7

    f = open(f'{signFile}', 'rb')
    byteSignMessage = f.read()
    bitString = ''.join(format(i, '08b') for i in byteSignMessage)

    pBitLength = p.bit_length()
    hashMessage = RWHash(7,pBitLength,bitString)

    r = FastExponential(g,k,p)
    kInverse = FindInverse(k, p-1)
    s = (kInverse * (hashMessage - (x * r))) % (p - 1)
    
    byteMessage = bytearray([int(bitString[i:i+8], 2) for i in range(0, len(bitString), 8)])

    Message = [int(bitString[i:i+8], 2) for i in range(0, len(bitString), 8)]
    Message.append(r)
    Message.append(s)

    extension = signFile.split('.')[-1]
    f = open(f'message.sign.{extension}', 'w')
    f.write(','.join(hex(x)[2:] for x in Message))

    f.close()

def verifyMessage(verifyFile, publicKey):
    p, g, y = publicKey
    # k = 7
    f = open(f'{verifyFile}', 'rb')
    signMessage = f.read().decode().split(",")
    
    r = int(signMessage[-2], 16)
    s = int(signMessage[-1], 16)

    signBinaryMessage = ''.join(format(int(signMessage[i], 16), '08b') for i in range(len(signMessage) - 2))
    pBitLength = p.bit_length()
    X = RWHash(7,pBitLength,signBinaryMessage)
    byteMessage = bytearray([int(signBinaryMessage[i:i+8], 2) for i in range(0, len(signBinaryMessage), 8)])

    gx = FastExponential(g,X,p)
    yr = FastExponential(y,r,p)
    rs = FastExponential(r,s,p)

    extension = verifyFile.split(".")[-1]
    if gx == (yr*rs) % p:
        f = open(f'verified-{verifyFile}', 'wb')
        f.write(byteMessage)
        f.close()
        return True
    return False

# fs = open(f'key.pub', 'rb')
# pKey = fs.read().decode().split(',')
# publicKey = int(pKey[0], 16), int(pKey[1], 16), int(pKey[2], 16)  
# ElgamalEncryptFile('KMITL.jpg',publicKey)
# fs = open(f'key.key', 'rb')
# privateKey = fs.read()
# ElgamalDecryptFile('KMITL.encrypt.jpg',privateKey)
while True:
    print('Please Select')
    print('1.Generate Prime')
    print('2.Find Inverse')
    print('3.Find Generator')
    print('4.Elgamal')
    print('5.Elgamal Key Generation')
    print('6.Elgamal Encrypt')
    print('7.Elgamal Decrypt')
    print('8.Sign')
    print('9.Verify')
    print('10.Hash')
    print('11.Exit')

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
        keySize = input('KeySize : ')
        file = input('File to read and gen key : ')
        publicKey, privateKey = ElgamalKeyGenerator(int(keySize),file)

        print('Public Key', ','.join(hex(x)[2:] for x in publicKey))
        print('Private Key', hex(privateKey)[2:])

        f = open(f'key.key', 'w')
        f.write(hex(privateKey)[2:])
        f = open(f'key.pub','w')
        f.write(','.join(hex(x)[2:] for x in publicKey))
        f.close()
        print('Generate Key Successfully')
    elif choice == '6':
        publicKeyf = input('Public Key File: ')
        enc = input('Encrypt File: ')
        fs = open(f'{publicKeyf}', 'rb')
        pKey = fs.read().decode().split(',')
        publicKey = int(pKey[0], 16), int(pKey[1], 16), int(pKey[2], 16)  
        ElgamalEncryptFile(enc,publicKey)
        fs.close()
    elif choice == '7':
        privateKeyf = input('Private key file: ')
        cipherTextf = input('Ciphertext file: ')
        fs = open(f'{privateKeyf}', 'rb')
        privateKey = fs.read()
        ElgamalDecryptFile(cipherTextf,privateKey)
        fs.close()
    elif choice == '8':
        privateKeyf = input('Private key file: ')
        publicKeyf = input('Public Parameters file (Public Key): ')
        signFile = input('Sign File: ')
        fs = open(f'{publicKeyf}', 'rb')
        pKey = fs.read().decode().split(',')
        publicKey = int(pKey[0], 16), int(pKey[1], 16), int(pKey[2], 16)    

        fs = open(f'{privateKeyf}', 'rb')
        privateKeyhex = fs.read()
        privateKey = int(privateKeyhex, 16)


        fs.close()

        signMessage(signFile, privateKey, publicKey)
    elif choice == '9':
        publicKeyf = input('Public Key file: ')
        fs = open(f'{publicKeyf}', 'rb')
        verifyFile = input('Verify file: ')
        pKey = fs.read().decode().split(',')
        publicKey = int(pKey[0], 16), int(pKey[1], 16), int(pKey[2], 16)  

        isVerified = verifyMessage(verifyFile,publicKey)

        if isVerified:
            print("This signature is Verified as True")
        else:
            print("Not Verified")


        fs.close()  
    elif choice == '10':
        plainTextf = input("File to hash : ")
        f = open(f'{plainTextf}', 'rb')
        plainText = f.read()
        bitString = ''.join(format(i, '08b') for i in plainText)
        p = input('Parameter p (Bit length): ')
        k = input('Parameter k: ')
        hashValue = RWHash(int(k),int(p),bitString)
        # bitString = ''.join(format(i, '08b') for i in byteSignMessage)
        print("Message Digest : ",hex(hashValue)[2:])
        extension = plainTextf.split('.')[-1]
        bitHash = format(hashValue,'08b')
        byteMessage = bytearray([int(bitHash[i:i+8], 2) for i in range(0, len(bitHash), 8)])
        f = open(f'hash.{extension}', 'wb')
        f.write(byteMessage)
        f.close()
    elif choice == '11':
        break
    else:
        continue
