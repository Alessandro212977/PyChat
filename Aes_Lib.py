#-----Alessandro--Canevaro-----#
#-Advanced-Encryption-Standard-#

#-LIBRARY-#

from copy import copy
from hashlib import sha256

#-CONSTANT-#

sbox = [ 
#-AES Substitution-box
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]

sbox_Inv = [
#-AES Substitution-box Inverted
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        ]

rcon = [
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
        ]

class AES():

    #-ALGORITHM-#

    #-SubBytes

    def subBytes(self, state): #state = lista
        """Operazione di sostituzione con la sbox"""
        for i in range(len(state)):
            state[i] = sbox[state[i]]

    def subBytesInv(self, state): #state = lista
        """SubBytes Inverso"""
        for i in range(len(state)):
            state[i] = sbox_Inv[state[i]]

     #-ShiftRows

    def rotate(self, word, n): #word = str, n = int
        """Restituisce 'word' spostata di 'n' posizioni"""
        return word[n:]+word[0:n]

    def shiftRows(self, state): #state = lista
        """Il passaggio ShiftRows provvede a scostare le righe della
        matrice di un parametro dipendente dal numero di riga"""
        for i in range(4):
            state[i*4:i*4+4] = self.rotate(state[i*4:i*4+4],i)

    def shiftRowsInv(self, state): #state = lista
        """ShiftRows Inverso"""
        for i in range(4):
            state[i*4:i*4+4] = self.rotate(state[i*4:i*4+4],-i)

    #-MixColumns

    def galoisMult(self, a, b): #a,b = int
        """Mltiplicazione nei campi di Galois"""
        p, BitSet = 0, 0
        for i in range(8):
            if b & 1 == 1:
                p ^= a
            BitSet = a & 0x80
            a <<= 1
            if BitSet == 0x80:
                a ^= 0x1b
            b >>= 1
        return p % 256

    def mixColumn(self, column): #column = lista
        """Operazione MixColumns effetuata solo su 1 'colonna'"""
        temp = copy(column)
        column[0] = self.galoisMult(temp[0],2) ^ self.galoisMult(temp[3],1) ^ \
                    self.galoisMult(temp[2],1) ^ self.galoisMult(temp[1],3)
        column[1] = self.galoisMult(temp[1],2) ^ self.galoisMult(temp[0],1) ^ \
                    self.galoisMult(temp[3],1) ^ self.galoisMult(temp[2],3)
        column[2] = self.galoisMult(temp[2],2) ^ self.galoisMult(temp[1],1) ^ \
                    self.galoisMult(temp[0],1) ^ self.galoisMult(temp[3],3)
        column[3] = self.galoisMult(temp[3],2) ^ self.galoisMult(temp[2],1) ^ \
                    self.galoisMult(temp[1],1) ^ self.galoisMult(temp[0],3)

    def mixColumnInv(self, column): #column = lista
        """"mixColumn Inverso"""
        temp = copy(column)
        column[0] = self.galoisMult(temp[0],14) ^ self.galoisMult(temp[3],9) ^ \
                    self.galoisMult(temp[2],13) ^ self.galoisMult(temp[1],11)
        column[1] = self.galoisMult(temp[1],14) ^ self.galoisMult(temp[0],9) ^ \
                    self.galoisMult(temp[3],13) ^ self.galoisMult(temp[2],11)
        column[2] = self.galoisMult(temp[2],14) ^ self.galoisMult(temp[1],9) ^ \
                    self.galoisMult(temp[0],13) ^ self.galoisMult(temp[3],11)
        column[3] = self.galoisMult(temp[3],14) ^ self.galoisMult(temp[2],9) ^ \
                    self.galoisMult(temp[1],13) ^ self.galoisMult(temp[0],11)

    def mixColumns(self, state): #state = lista
        """Il passaggio MixColumns prende i quattro elementi di ogni colonna e li
        combina utilizzando una trasformazione lineare invertibile"""
        for i in range(4):
            column = [] #Crea una colonna prendendo i valori con
            for j in range(4): #lo stesso indice dalle varie righe
                column.append(state[j*4+i])
            self.mixColumn(column) #Mixcolumn sulla colonna appena creata
            for j in range(4): #Trsferisce i nuovi valori nella matrice principale
                state[j*4+i] = column[j]

    def mixColumnsInv(self, state): #state = lista
        """MixColumns Inverso"""
        for i in range(4):
            column = []
            for j in range(4):
                column.append(state[j*4+i])
            self.mixColumnInv(column)
            for j in range(4):
                state[j*4+i] = column[j]

    #-AddRoundKey

    def addRoundKey(self, state, roundKey): #state = lista
        """AddRoundKey combina con uno XOR la chiave di sessione con
        la matrice ottenuta dai passaggi precedenti (State).""" 
        for i in range(len(state)):
            state[i] = state[i] ^ roundKey[i]
        
    #-KEY-#
       
    def passwordToKey(self, password): #password = str
        """create a key from a user-supplied password using SHA-256"""
        psw_sha = sha256(password.encode('utf-8')) #sha256 hash
        key = []
        for c in list(psw_sha.digest()):
            key.append(c)
        return key #chiperKey
 
    def keyScheduleCore(self, word, i):
        """XOR the output of the rcon transformation 
        with the first part of the word"""
        word = self.rotate(word, 1)
        newWord = []
        for byte in word: 
            newWord.append(sbox[byte]) 
        newWord[0] = newWord[0]^rcon[i]
        return newWord

    def expandKey(self, cipherKey):
        """expand 256 bit cipher key into 240 byte key
        from which each round key is derived"""
        cipherKeySize = len(cipherKey)
        assert cipherKeySize == 32
        expandedKey = [] # container for expanded key
        currentSize = 0
        rconIter = 1
        t = [0,0,0,0] # temporary list to store 4 bytes at a time
        # copy the first 32 bytes of the cipher key to the expanded key
        for i in range(cipherKeySize):
            expandedKey.append(cipherKey[i])
        currentSize += cipherKeySize
        # generate the remaining bytes until we get a total key size of 240 bytes
        while currentSize < 240:
            # assign previous 4 bytes to the temporary storage t
            for i in range(4):
                t[i] = expandedKey[(currentSize - 4) + i]
            # every 32 bytes apply the core schedule to t
            if currentSize % cipherKeySize == 0:
                t = self.keyScheduleCore(t, rconIter)
                rconIter += 1
            # since we're using a 256-bit key -> add an extra sbox transform
            if currentSize % cipherKeySize == 16:
                for i in range(4):
                    t[i] = sbox[t[i]]
            # XOR t with the 4-byte block [16,24,32] bytes before the end of the
            # current expanded key.  These 4 bytes become the next bytes in the
            # expanded key
            for i in range(4):
                expandedKey.append((expandedKey[currentSize - cipherKeySize]) ^ (t[i]))
                currentSize += 1 
        return expandedKey

    def createRoundKey(self, expandedKey, n):
        """returns a 16-byte round key based on an
        expanded key and round number"""
        return expandedKey[(n*16):(n*16+16)] #RoundKey

    #-AES-MAIN-#

    def aesRound(self, state, roundKey):
        """Un round applica le 4 Trsformazioni"""
        self.subBytes(state)
        self.shiftRows(state)
        self.mixColumns(state)
        self.addRoundKey(state, roundKey)

    def aesRoundInv(self, state, roundKey):
        """aesRound Inverso"""
        self.addRoundKey(state, roundKey)
        self.mixColumnsInv(state)
        self.shiftRowsInv(state)
        self.subBytesInv(state)

    def aesMain(self, state, expandedKey, numRounds=14):
        """AES 14 Rounds (encrypt)"""
        roundKey = self.createRoundKey(expandedKey, 0)
        self.addRoundKey(state, roundKey)
        for i in range(1, numRounds):
            roundKey = self.createRoundKey(expandedKey, i)
            self.aesRound(state, roundKey)
        #Round finale senza MixColumns
        roundKey = self.createRoundKey(expandedKey, numRounds)
        self.subBytes(state)
        self.shiftRows(state)
        self.addRoundKey(state, roundKey)

    def aesMainInv(self, state, expandedKey, numRounds=14):
        """AES 14 Rounds (decrypt)"""
        roundKey = self.createRoundKey(expandedKey, numRounds)
        self.addRoundKey(state, roundKey)
        self.shiftRowsInv(state)
        self.subBytesInv(state)
        for i in range(numRounds-1,0,-1):
            roundKey = self.createRoundKey(expandedKey, i)
            self.aesRoundInv(state, roundKey)
        #Round finale senza MixColumns
        roundKey = self.createRoundKey(expandedKey, 0)
        self.addRoundKey(state, roundKey)

    def aesEncrypt(self, plaintext, key): #plaintext = list(16), key = passwordToKey()
        """Critta un 'blocco' di 16 caratteri(ord())"""
        block = copy(plaintext)
        expandedKey = self.expandKey(key)
        self.aesMain(block, expandedKey)
        return block

    def aesDecrypt(self, ciphertext, key): #ciphertext = list(16), key = passwordToKey()
        """Decritta un 'blocco' di 16 caratteri(ord())"""
        block = copy(ciphertext)
        expandedKey = self.expandKey(key)
        self.aesMainInv(block, expandedKey)
        return block

    #-SUB-MAIN-#

    def getBlock(self, string): #string = str
        """Trasforma una stringa di 16 caratteri in un 'Block'"""
        block = []
        for c in list(string):
            block.append(ord(c))
        if len(block) < 16:
            padChar = 16-len(block)
            while len(block) < 16:
                block.append(padChar)
        #print('this is the block ', block)
        return block

    def encrypt(self, plaintext, password): #plaintext, pssaword = str
        """Critta una stringa di lunghezza variabile"""
        chipertext = ''
        mess_l = len(plaintext)
        key = self.passwordToKey(password)
        for i in range((len(plaintext)//16)+1):
            Block = self.getBlock(plaintext[i*16:i*16+16])
            chiper = self.aesEncrypt(Block,key)
            for j in chiper:
                chipertext += chr(j)
        chip_l = len(chipertext)
        pad = chip_l - mess_l
        if pad < 10:
            pad = '0'+str(pad)
        return str(pad)+chipertext
 
    def decrypt(self, chipertext, password): #plaintext, pssaword = str
        """Decritta una stringa di lunghezza variabile"""
        if len(chipertext) == 0:
            return ''
        message = ''
        pad = int(chipertext[0:2])
        chipertext = chipertext[2:]
        key = self.passwordToKey(password)
        for i in range(len(chipertext)//16):
            Block = self.getBlock(chipertext[i*16:i*16+16])
            plaintext = self.aesDecrypt(Block, key)
            for j in plaintext:
                message += chr(j)
        return message[:len(message)-pad]

    #other
    
    def encode4(self, string):
        code = ''
        for char in string:
            var = str(ord(char))
            if len(var) == 5:
                return self.encode4('Invalid Char')
            while len(var) != 4:
                var = '0' + var
            code += var
        return '9'+code

    def decode4(self, code):
        code = code[1:]
        string, char = '', ''
        for var in code:
            char += var
            if len(char) == 4:
                string += chr(int(char))
                char = ''
        return string

if __name__ == '__main__':
    print('Advanced Encryption Standard (Galois counter mode)')

    def test():
        test = AES()
        print('Test Started... \n')
        print('encrypt: msg = Hello, psw = password')
        c = test.encrypt('Hello', 'password')
        #print(c,'\n')
        p = test.decrypt(c, 'password')
        print('decrypt: msg = Secret msg, psw = password')
        print(p)
        print(test.encode4('Invalid Char'))
        print(test.decode4(test.encode4('ciao')))

    test()
