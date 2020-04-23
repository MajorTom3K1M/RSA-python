import random
from math import sqrt 

def findInverse(n2, n1):
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

def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b

def fexpo(base, expo, mod):
    result = 1
    if 1 & expo:
        result = base  
    while expo:
        expo = expo >> 1
        base = (base * base) % mod
        if expo & 1:
            result = (base * result) % mod
    return result

def lehmann(n, t):
    a = random.randint(2, n-1)
    expo = (n-1)//2

    while t>0:
        result = fexpo(a,expo,n)

        if result == 1 or result == n-1:
            a = random.randint(2, n-1)
            t -= 1
        else: 
            return False # Not Prime
    return True # Prime

def primeFactors(s, n):
    while n % 2 == 0:
        s.add(2)
        n = n // 2

    for i in range(3, int(sqrt(n)) ,2):
        while n % i == 0:
            s.add(i)
            n = n // i

    if n > 2:
        s.add(n)


def findSmallestGenerator(n):
    s = set()

    if lehmann(n, 1000) == False:
        return -1
    
    p = n - 1

    primeFactors(s, p)

    for r in range(2, p + 1):
        flag = False
        for element in s:
            if fexpo(r, p // element, n) == 1:
                flag = True
                break
        if flag == False:
            # print(r)
            return r 
    
    return -1

def generateLargePrime(keysize):
    while True:
        num = random.randrange(2**(keysize-1),2**(keysize))
        if lehmann(num, 1000):
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
    
    d = findInverse(e, m)
    publicKey = (n, e)
    privateKey = (n, d)
   
    return (publicKey, privateKey)

# publicKey, privateKey = generateKey(100)
# print("generate publicKey ", publicKey)
# print("generate privateKey ", privateKey)

def genP(n, file):
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
            if lehmann(decimal, 1000):
                return decimal
            decimal += 1
    else:
        return -1

def getGenerator(alpha, p):
    if lehmann(p, 1000) == False:
        return -1
    
    if fexpo(alpha, (p - 1)//2, p) != 1:
        return alpha
    else: 
        return -alpha % p

def findGenerator(p):
    s = set()

    while len(s) <= 2:
        alpha = random.randrange(2, p-1)
        g = getGenerator(alpha, p)
        s.add(g)
    
    return s

print(genP(18,"original.txt"))
print(findGenerator(genP(18,"original.txt")))