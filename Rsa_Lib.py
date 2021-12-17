#-Alessandro Canevaro
#-Rsa_Lib

from random import randrange, randint

class Prime:

    '''random generation functions
    for big prime numbers'''

    def Fermat(num):
        '''Fermat probabilistic prime test'''
        assert type(num) == int, 'Need int-type number'

        if num == 2:
            return True
        elif num & 0:
            return False
        else:
            return pow(2, num-1, num) == 1

    def randprime(start = 2, stop = 2):
        '''generate a random prime number in the given range'''
        if stop<start:
            start, stop = 2, start
        if start%2 == 0:
            start += 1
        while True:
            n = randrange(start, stop, 2)
            if Prime.Fermat(n):
                    return n

class Rsa_Key:

    '''#-Asymmetric encryption system based on RSA algorithm-#
    RSA Lib 3.0.0 for python 3.x
    
    300 digits = 4096 bits keys'''

    def GCD(a, b):
        '''Greatest common divisor'''
        while b:
            a, b = b, a % b
        return a

    def Inverse(a, n):
        '''Modular integers (a*t=1 mod n)'''
        t, newt = 0, 1
        r, newr = n, a
        while newr != 0:
            quotient = r // newr
            t, newt = newt, t-quotient * newt
            r, newr = newr, r-quotient * newr
        if t < 0 :
            t = t+n
        return t

    def Raw_Key(digits = 300):
        '''Generate e, d, n following rsa algorithm'''
        p = Prime.randprime(10**digits, 10**(digits+1))
        q = Prime.randprime(p+1, 10**(digits+2))
        n = p*q
        f = (p-1)*(q-1)
        #Generate E
        while True:
            e = randint(p+1, f-1)
            if Rsa_Key.GCD(e, f) == 1:
                break
        #Generate D
        d = Rsa_Key.Inverse(e, f)
        return e, d, n # (e,n); (d,n)

    def Hex_Key(digits = 300):
        e, d, n, = Rsa_Key.Raw_Key(digits)
        kpu = hex(e) +'@'+ hex(n)
        kpr = hex(d) +'@'+ hex(n)
        return kpu, kpr
      
    def Doc_Key(digits = 300):
        Kpu, Kpr = Rsa_Key.Hex_Key(300)
        with open('RSA_Pubblic_Key.doc','w') as file:
            file.write(Kpu)
        with open('RSA_Private_Key.doc','w') as file:
            file.write(Kpr)

class RSA:
    
    '''#-Asymmetric encryption system based on RSA algorithm-#
    RSA Lib 3.0.0 for python 3.x'''

    def Encode(text):
        assert type(text) == str, 'TypeError: a string is required'
        array = list(ord(i) for i in text)
        pad = str(len(str(max(array))))
        code = pad
        for i, value in enumerate(array):
            code += '0'*(int(pad)-len(str(value))) + str(value)
        return code

    def Decode(code):
        assert type(code) == int or type(code) == str, 'TypeError: an integer or a string is required'
        pad = int(str(code)[0])
        code = str(code)[1:]
        text = ''
        for i in range(0, len(code), pad):
            text += chr(int(code[i:i+pad]))
        return text

    def Raw_Encrypt(e, n, code):
        m = int(code)
        return pow(m, e, n)

    def Raw_Decrypt(d, n, code):
        c = int(code)
        return pow(c, d, n)

    def Hex_Encrypt(Kpu, code):
        x = Kpu.split('@')
        c = RSA.Raw_Encrypt(int(x[0], 16), int(x[1], 16), code)
        return hex(c)

    def Hex_Decrypt(Kpr, code):
        x = Kpr.split('@')
        m = RSA.Raw_Decrypt(int(x[0], 16), int(x[1], 16), int(code, 16))
        return m

    def Read_Key(Directory):
        with open(Directory, 'r') as file:
            key = file.read()
        return key

    def Fingerprint(Key, CAKpr, CAKpu = None):
        from hashlib import sha1
        f = RSA.Hex_Encrypt(CAKpr, RSA.Encode(sha1(Key.encode()).hexdigest()))
        if CAKpu != None:
            assert sha1(Key.encode()).hexdigest() == RSA.Decode(str(RSA.Hex_Decrypt(CAKpu, f))), 'Testing Fingerprint Authentication failed'
        return f

class TEST:
    
    def prime_statistics():
        from time import time
        import statistics
        results = []
        for i in range(9,10):
            print('i:', i)
            temp = []
            for j in range(1000):
                t0 = time()
                n = Prime.randprime(10**(i*10), 10**((i*10)+1))
                temp.append((time()-t0)*10000)
                m = statistics.mean(temp)
            results.append((m, statistics.pstdev(temp, m)))
            for k in temp:
                print(k)
            
                
        for a, b in results:
            print('Media: %1.3f' %a, 'Deviazione standard: %1.3f' %b)

    def data(_iter = 100000, size = 100):
        from time import time
        with open('stat.txt', 'a') as f:
            print('start')
            for i in range(_iter):
                t0 = time()
                n = Prime.randprime(10**size, 10**(size+1))
                f.write((str((time()-t0)*10000)).split('.')[0]+'\n')
        print('finish')

    def freq(file = 'stat.txt'):
        import statistics
        dataset, freq = [], []
        with open(file, 'r') as f:
            for line in f:
                dataset.append(int(line)//10)
        dataset.sort()
        for i in range(max(dataset)+1):
            freq.append(0)
        for j in dataset:
            freq[j] = freq[j]+1
        print('media', statistics.mean(dataset), 'mediana', statistics.median(dataset), 'moda', statistics.mode(dataset))
        print('dvst', statistics.pstdev(dataset))
        #for i, k in enumerate(freq):
            #print(k)
            
        

if __name__ == '__main__':
    #TEST.prime_statistics()
    TEST.freq()
##    kpu = '0x18603ed8a8d203a72e1f29f632d7e459e015f86ce57d964ad30f73414715e45beabee303b8d4b93d3496afbd2b4e2c950b83b82df4e2df6bc0fe1c08de8a98b1148659959e93b9c24b8a0118489093867adabab704fd89bbd4daf91d153916d59c262ece64764922dc2d733fab45d97c9c4c7d5ad6d23a19a70b1307e7a5dcd1e3255c961a7722a5b5258c5d4eeb98203a71b38bed14fc60072d73b0ceeeda2df5f6789df55d253ee0bffe1c9f72984735a8ca7d86eb4e4f6ef09b7c7c5de36d790257dd5d93980e2ad4fd57f7d6aba1099aff2c2faf62f8123383bf8be936b1368cb47b025e3fb25e928fc72aee83e8c0134c44d61a96c166f69@0x445e5f2b56b8fbe504314c274c8a706306966446332742bef2e012e9f4c0bb61c808fdbe735a15ef422fabc5e138079d5d6849fe4cd735b1cf553b6fa3dd7a9c22c0a3a33ad05a4afd75682e53b340782d897a02d97462efcab4f31be755745b7a5d6e8781d25e7184cae855f240d7d1d25f92ce833091d367788d5924829b407d9605abf8c3a393017cf773f71341b55a2a5d505437232ef5720c4be4838d0e8515e4c49e5b04debfd42c7e376736e4d905aa18ecc06a7f6b50a98de772eb589d5687c4627460f9cc4172749de4898bf0621b7be9adef86a1813534c7d1e77bc31076c62dda88023e2b7b1443a82766d9b008ea43db4b6dc8617'
##    CAkpr = '0x5045a8a434778ec086ea49272eff13cc9f1c3884529206176911435e9eaa66c894a8f9edb6e2ad206f57ceb22ed216280c7fe34839f2e27ea709a4e589f636add5719d78792ab31d34ec47f82b9f53728e0e870e3c55e8e0ecbd60ddadf51ba6e4615f730dc7b550ce3340ddc458e38231112bf5726136b4e0170a5731a3687e817cd4ade0b4ebd1586ec50ebd15bf3eef9b321b6749cba1c676aca75cf48f72b9224ca88bc63e4a012bda650cf9d65587305488f4c02738daeafb4d12511533767ac5ec2f8cceccea873e931e6f1ff090c6cbf834f0899f5404726311cb79337fb682833c7e3fe5a12461ce335fabdd78ce6f5dcaee35c4355f74efeb4eb7a457e0844436117f5b853ef1bce1eb1ae19ce3bc3c98bc57e5ad85a56bec1947505e06fb1f670b69697f49b5b27d828b5c668bdbaff4629150623899ef711f7e02303dfd373b2777b84e613a71697581106f9355ee84485c4647d0e41c46101a198087950f84d988366c1efbcd0bb58ee4679c34ddcb0b8f1505080b345afce79f3322c380f005194b4a0b0bf675e4f87598c87b5ebc5f83eb7f58169de431b91795c93c163a9309094f933d10675d4c2c31685ebf7cca1ab99b57c3d22afd3f75309598dbf6b6dd72d69c41080c613ce3cc6b90e3fb9f371e74e7cd908587d6f31da0ecc70c6822adbb94a8f66e2a9ec916e477@0x500a15aa7b1c224f3be5c8b49598c0af23bfedad35902a31f0ed2946ee363bab7464cfb5b7ad01e39cdd8926f5ba248fc9e9f7d33d3529ec9123e93c20d8b714ab07ea1784dc675bf6a0365ff80416f75835819c4a5ada06ceaddfaae309c631c3c5778d3adda3aaa3c7ad84315e98535df515f2253a728b94b9b8d45f47a781bbc384f7ee4b004f1f6a00af84ff645ff5f9d1933fb89299591d9a7ec8227e7f99da7ec5c6393660f9f92a9544575b49135d3d408ee664237da5d47c07c0a22f453013a497527782f2131488f2840ffcbdc71b6e2dbe2e4b47a5f4bb3caccf643a5d4c2667fde9d229e85d7e50e2a4b764f3ac32538ca0c2d6c46cbb0202abce4409d9d5b0f78ffdaa0d5486f9374d038d7a7858fdfab95d45bf4f4aa0eab609a90e2667c75e5d58dfa6ecf4dcb88add517e1e6b446ae2f66dcf575bfbeb35be1d6602076fdc7d70e2d4152238f5757f9be3d3353192504635dacd7126bbcfd38700dfeeadf02ff3b00a2bdd6350cf91ff4be5bfe33612d169a0848c47773c034f2ca14aacda993986d16058eacba1ba17c96071b4b4936263b0d5bf756dd9e160656742953b50bb92de0f53b60ab8da2248c662454904aea52e30bc0329a3b4f21210fd90ed605c9495274673ebd1ee0f5411c92b5b5b5d2f2c84423b06c67b544f329fdb308bd51f648554989414b57129089'
##    CAkpu = '0x2dc4aed42ec7fad564c3430388cecd853c9692927bca7f13bc598c0e2757841741c3b23649fdddc3463b2ae787b049bec79a3b213b0481a6d333e828c0aba58d4ae39f15f08ec90a6f6b6b658a630e25ee2c4d19a7fb90e2165baa83b6bc189dc922cecd18bc14f433797a1a12990b2483040a662a3c7f742f559a14f6f8dffaf67e6fd1e0f2c7fcf8b0e40404f7c6ff60e256e546832897aa1b0638f7d39dfa6764dab3cce16962e5f908eb896c0fefe38958a51c3b9bb00a0e92b52e44f255d98dec215e7439bdbabb53b9a49676e6a2630291278636c14017dfb60a5fa56bada8fc2479036c48ee3e295d445a2b1bac3bb1f153ef2035729975911d1445be0c0631f31baa1b5f2faff39089bc689e2827c4b0d29a2743c78594ece188c3946bb50f40e176eb1616e96ea4f89b981c7c868e24fdf7a72e5f2e6b8a94c443fdd9e4e73411838580b081f4b58d349b0e8d85f5d4b019a0bf606060b76ddf219f6b36924e0718b3cdab19464083b946ca9a0a2e4af20f1eab121d20af70ae449eaf3b7017118380bf4ced24c80dde44916a1f67b54fe212001a55f0b136f99de71750cfacdbc09ce56812101109624aa0a131f6c70bcc34f4a8f559f0db1a943fdb6fa705c6b1d81f967fad0f845693c589643c06b759c10e2270ed269499bf66b45322905109f74ff8afd47a052c5a058dc2d17@0x500a15aa7b1c224f3be5c8b49598c0af23bfedad35902a31f0ed2946ee363bab7464cfb5b7ad01e39cdd8926f5ba248fc9e9f7d33d3529ec9123e93c20d8b714ab07ea1784dc675bf6a0365ff80416f75835819c4a5ada06ceaddfaae309c631c3c5778d3adda3aaa3c7ad84315e98535df515f2253a728b94b9b8d45f47a781bbc384f7ee4b004f1f6a00af84ff645ff5f9d1933fb89299591d9a7ec8227e7f99da7ec5c6393660f9f92a9544575b49135d3d408ee664237da5d47c07c0a22f453013a497527782f2131488f2840ffcbdc71b6e2dbe2e4b47a5f4bb3caccf643a5d4c2667fde9d229e85d7e50e2a4b764f3ac32538ca0c2d6c46cbb0202abce4409d9d5b0f78ffdaa0d5486f9374d038d7a7858fdfab95d45bf4f4aa0eab609a90e2667c75e5d58dfa6ecf4dcb88add517e1e6b446ae2f66dcf575bfbeb35be1d6602076fdc7d70e2d4152238f5757f9be3d3353192504635dacd7126bbcfd38700dfeeadf02ff3b00a2bdd6350cf91ff4be5bfe33612d169a0848c47773c034f2ca14aacda993986d16058eacba1ba17c96071b4b4936263b0d5bf756dd9e160656742953b50bb92de0f53b60ab8da2248c662454904aea52e30bc0329a3b4f21210fd90ed605c9495274673ebd1ee0f5411c92b5b5b5d2f2c84423b06c67b544f329fdb308bd51f648554989414b57129089'
    #print(RSA.Encode('ciao☑'))
    #print(RSA.Decode(RSA.Encode('ciao☑')))
##    print(RSA.Fingerprint(kpu, CAkpr, CAkpu))
