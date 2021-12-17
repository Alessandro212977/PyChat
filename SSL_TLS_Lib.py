from hashlib import sha1, md5
from hmac import HMAC
from random import choice
from Rsa_Lib import RSA

class SSL_TLS:

    '''ssl/tls function
    Session_State = {'Client_Kpu':None, 'Server_Kpu':None, 'Client_Kpr':None, 'Server_Kpr':None, 'Session_ID':None, 'DHE_Params':{'Common_Base':None, 'Common_Z':None, 'Client_PreMasterSecret':None, 'Server_PreMasterSecret':None, 'Master_Secret':None}, 'Client_Final_Hash':None, 'Server_Final_Hash':None}'''

    #Hello Message

    def ClientHelloMessage_Encode(Session_State):
        '''Build the hello Message for Server. Client Kpu, Common Base, Session Id'''
        Mess = '[SSL/TLS]&[CLIENT HELLO]'
        Mess += '&Client_Kpu='+str(Session_State['Client_Kpu'])
        Mess += '&Session_ID='+str(Session_State['Session_ID'])
        Mess += '&DHE_Params=Common_Base:'+str(Session_State['DHE_Params']['Common_Base'])
        return Mess

    def ServerHelloMessage_Encode(Session_State):
        '''Build the hello Message for Client. Server Kpu, Common Z, Session Id'''
        Mess = '[SSL/TLS]&[SERVER HELLO]'
        Mess += '&Server_Kpu='+str(Session_State['Server_Kpu'])
        Mess += '&Session_ID='+str(Session_State['Session_ID'])
        Mess += '&DHE_Params=Common_Z:'+str(Session_State['DHE_Params']['Common_Z'])
        return Mess
    
    def ClientHelloMessage_Decode(Session_State, Mess):
        '''Update the Session State with the client message'''
        args = Mess.split('&')
        if args[0] == '[SSL/TLS]' and args[1] == '[CLIENT HELLO]' and len(args) == 5:
            for arg in args[2:]:
                couple = arg.split('=')
                if couple[0] == 'DHE_Params':
                    dhe = couple[1].split(':')
                    Session_State['DHE_Params'] [dhe[0]] = dhe[1]
                else:
                    Session_State[couple[0]] = couple[1]
        return Session_State

    def ServerHelloMessage_Decode(Session_State, Mess):
        '''Update the Session State with the client message'''
        args = Mess.split('&')
        if args[0] == '[SSL/TLS]' and args[1] == '[SERVER HELLO]' and len(args) == 5:
            for arg in args:
                couple = arg.split('=')
                if couple[0] in Session_State:
                    if couple[0] == 'DHE_Params':
                        dhe = couple[1].split(':')
                        Session_State['DHE_Params'] [dhe[0]] = dhe[1]
                    else:
                        Session_State[couple[0]] = couple[1]
        return Session_State

    #Certificate

    def Import_Certificate(directory):
        '''Read the certificate and return a dict with the info'''
        C_Dict = {'Serial_Number':None, 'Signature_Algorithm':None, 'Not_Before':None, 'Not_After':None, 'ICN':None, 'IC':None, 'IST':None, 'IO':None, 'IOU':None, 'IKpu':None, 'SCN':None, 'SC':None, 'SST':None, 'SO':None, 'SOU':None, 'SKpu':None, 'FP':None}
        file = open(directory, 'r')
        for line in file:
            args = line.split('=')
            if args[0] in C_Dict:
                C_Dict[args[0]] = args[1] [:-1]
        file.close()
        return C_Dict

    def Validate_Certificate(C_Dict, Supreme_C_Dict):
        '''Control if a certificate is valid'''
        if C_Dict['IKpu'] == Supreme_C_Dict['SKpu']:
            Test_Key = sha1(C_Dict['SKpu'].encode()).hexdigest()
            CA_Kpu = Supreme_C_Dict['SKpu']
            if Test_Key == RSA.Decode(str(RSA.Hex_Decrypt(CA_Kpu, C_Dict['FP']))):
                return True
        return False

    def Certificate_Encode(C_Dict):
        '''Build the Certificate message from a C_Dict'''
        Mess = '[SSL/TLS]&[CERTIFICATE]'
        for args in C_Dict:
            Mess += '&'+str(args)+'='+str(C_Dict[args])
        return Mess

    def Certificate_Decode(Mess):
        '''Transform a 'string format' certificate into a C_Dict'''
        C_Dict = {'Serial_Number':None, 'Signature_Algorithm':None, 'Not_Before':None, 'Not_After':None, 'ICN':None, 'IC':None, 'IST':None, 'IO':None, 'IOU':None, 'IKpu':None, 'SCN':None, 'SC':None, 'SST':None, 'SO':None, 'SOU':None, 'SKpu':None, 'FP':None}
        Mess = Mess.split('&')
        for args in Mess:
            key = args.split('=')
            if key[0] in C_Dict:
                C_Dict[key[0]] = key[1]
        return C_Dict

    #Key Exchange

    def Key_Exchange_Encode(Session_State, target):
        '''Build target(client or server) key exchange message'''
        Mess = '[SSL/TLS]&['+target.upper()+' KEY EXCHANGE]'
        Mess += '&DHE_Params='+target.capitalize()+'_Pre_Master_Secret:'+str(Session_State['DHE_Params'] [target.capitalize()+'_Pre_Master_Secret'])
        return Mess

    def key_Exchange_Decode(Mess, Session_State):
        '''Update the Session_State with the key exchange message infos'''
        Mess = Mess.split('&')[2].split('=')[1].split(':')
        if Mess[0] in Session_State['DHE_Params']:
            Session_State['DHE_Params'] [Mess[0]] = Mess[1]
        return Session_State

    #Final hash

    def HMAC_SHA1(Session_State):
        '''Build the hmac with sha1 of the current session state'''
        KEY = str(md5((str(Session_State['Client_Kpu'])+str(Session_State['Server_Kpu'])).encode()).hexdigest())
        DHE = str(md5(str(Session_State['DHE_Params']['Client_Pre_Master_Secret']+Session_State['DHE_Params']['Server_Pre_Master_Secret']).encode()).hexdigest())
        return HMAC(KEY.encode(), DHE.encode(), sha1).hexdigest() #str(Session_State['Session_ID']).encode(), 

    def Finish_Encode(Session_State, Target):
        '''Build the final hash message for the target(client or server) with session state informations'''
        Mess = '[SSL/TLS]&[FINISH]'
        Mess += '&'+Target.capitalize()+'_Final_Hash'+'='+str(Session_State[Target.capitalize()+'_Final_Hash'])
        return Mess

    def Finish_Decode(Mess, Session_State):
        '''Read the string format final hash and return the updated session state'''
        Mess = Mess.split('&')[2].split('=')
        if Mess[0] in Session_State:
            Session_State[Mess[0]] = Mess[1]
        return Session_State

    #ID Genrator

    def Salt():
        '''Salt generator'''
        char = list(chr(i) for i in range(65, 123) if i < 91 or i > 96) #<-quanto è bella questa riga! :)
        while True:
            yield choice(char)

    def ID(Lenght = 64):
        '''Create a random ID for the Session'''
        salt = ''
        for i in range(Lenght):
            salt += next(SSL_TLS.Salt())
        h = sha1(salt.encode())
        return h.hexdigest() 

    #Other functions

    def Key_Load(directory):
        '''Read RSA key from a file'''
        doc = open(directory, 'r')
        key = doc.read()
        doc.close()
        return key

    def ID_Import(directory = 'ID.doc'):
        id_list = {}
        try:
            with open(directory, 'r') as file:
                for line in file:  
                    line = line[:-1]
                    args = line.split('==')
                    id_list[args[0]] = args[1]
            return id_list
        except FileNotFoundError:
            return None

    def ID_Export(ID, PSW, directory = 'ID.doc', mode = 'w'):
        with open(directory, mode) as file:
            file.write(str(ID)+'=='+str(PSW)+'\n')
                        
class MAC:

    def Mac_Creator(data):
        '''return a sha1 mac of the mess'''
        h = sha1(str(data).encode()).hexdigest()
        return '[MAC]%%%'+data+'%%%'+h

    def Mac_Check(data):
        '''check the mac of a mess'''
        info = data.split('%%%')
        if info[0] == '[MAC]':
            h = sha1(str(info[1]).encode()).hexdigest()
            if h == info[2]:
                return info[1]
        return 0
