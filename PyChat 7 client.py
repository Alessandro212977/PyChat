#Alessandro Canevaro
#Client for PyChat® 7
#18/FEB/2016

#Libraries
import socket
from _thread import start_new_thread
from time import strftime, sleep
from hashlib import sha1

from Aes_Lib import AES
from Rsa_Lib import RSA, Prime
from SSL_TLS_Lib import MAC
from SSL_TLS_Lib import SSL_TLS as ssl
from GUI_7 import PYCG

aes = AES()
grp = PYCG(socket.gethostname())

#Constant

host_name = socket.gethostname()
server_name = 'ALE-ZBK'
port = 8888

Operating_State = {'DEBUG':True, 'MAC':True, 'ENCRYPTION':True} 

server_info = {'sock':'', 'password':''}

File = {'Client_Kpu': 'Ale_Pubblic_Key.doc', 'Client_Kpr': 'Ale_Private_Key.doc',
        'Client_CA': 'Ale_CA.doc', 'Supreme_CA': 'CA.doc'}

Error = {'type':'Arguments must be string type.',
         'disconnected':'[SOCKET][INFO] Server has disconnected (data_recive)'}

Command = {'Server_Conn': grp.connection} 

#Functions

ct = lambda:'['+strftime('%X')+']' #Returns the current time

class data:
    '''Data manipulation functions'''

    def check_in(Mess, server_info):
        '''provides encryption, Mac creation and encoding data if request in OPS'''
        assert (type(Mess) == str and type(server_info['password']) == str), Error['type']
        if Operating_State['ENCRYPTION']:
            Mess = aes.encode4(Mess)
            Mess = aes.encrypt(Mess, server_info['password'])
        if Operating_State['MAC']:
            Mess = MAC.Mac_Creator(Mess)
        Mess = Mess.encode()
        return Mess

    def check_out(Mess, server_info):
        '''provides decryption, Mac checking and decoding data if request in OPS'''
        Mess = Mess.decode()
        assert (type(Mess) == str), Error['type']
        if Operating_State['MAC']:
            Mess = MAC.Mac_Check(Mess)
        if Operating_State['ENCRYPTION']:
            Mess = aes.decrypt(Mess, server_info['password'])
            Mess = aes.decode4(Mess)
        return Mess

    def loader(server_info):
        while True:
            sleep(0.01)
            Mess = grp.idata()
            if Mess != '':
                data.send(Mess, server_info)

    def send(Mess, server_info): #error managing
        '''Send data to the 'name' socket'''
        Mess = data.check_in(Mess, server_info)
        server_info['sock'].send(Mess)

    def recive(server_info): #error managing
        '''Function to thread'''
        while True:
            try:
                Mess = server_info['sock'].recv(6144)
                Mess = data.check_out(Mess, server_info)
                data.manager(Mess)
            except ConnectionResetError:
                grp.LoadMyInfo(ct()+Error['disconnected'])
                break
 
    def manager(Mess):
        l = str(Mess).split('&£&')
        if l[1] == '[DATA]':
            grp.LoadOtherEntry(l[2])
        elif l[1] == '[COMMAND]':
            if l[2] in Command:
                Command[l[2]](l[3].split('&&&'))
                grp.LoadMyInfo('Command executed successfully')
            else:
                grp.LoadOtherInfo(Mess)
        else:
            grp.LoadMyInfo(ct()+Error['Unexpected data'])

def Handshake(sock):
    '''ssl/tls handshake'''
    grp.LoadMyInfo(ct()+'[SSL/TLS] [INFO] Handshake started')

    Session_State = {'Client_Kpu': RSA.Read_Key(File['Client_Kpu']), 'Server_Kpu': None, 
                     'Client_Kpr': RSA.Read_Key(File['Client_Kpr']), 'Session_ID': None, #ssl.ID_Import(),
                     'Client_CA': ssl.Import_Certificate(File['Client_CA']),
                     'Supreme_CA': ssl.Import_Certificate(File['Supreme_CA']),
                     'DHE_Params': 
                     {'Common_Base': Prime.randprime(10**50, 10**55), 'Common_Z':None, 
                      'Client_Random': Prime.randprime(10**300, 10**310), 
                      'Client_Pre_Master_Secret': None, 'Server_Pre_Master_Secret': None, 
                      'Master_Secret': None}, 
                     'Client_Final_Hash': None, 'Server_Final_Hash': None}

    grp.LoadMyInfo(ct()+'[SSL/TLS] [INFO] Session_State ready')
    
    try:
        #Client Hello Message
        CHM = ssl.ClientHelloMessage_Encode(Session_State)
        sock.send(CHM.encode())
        grp.LoadMyInfo(ct()+'[SSL/TLS] [INFO] Client Hello Message send')

        #Server Hello Message
        SHM = sock.recv(8192).decode()
        Session_State = ssl.ServerHelloMessage_Decode(Session_State, SHM)
        grp.LoadMyInfo(ct()+'[SSL/TLS] [INFO] Recived Server Hello Message')

        #Client Certificate
        CC = ssl.Certificate_Encode(Session_State['Client_CA'])
        sock.send(CC.encode())
        grp.LoadMyInfo(ct()+'[SSL/TLS] [INFO] Client Certificate send')

        #Server Certificate
        SC = sock.recv(8192).decode()
        Server_CA = ssl.Certificate_Decode(SC)
        if ssl.Validate_Certificate(Server_CA, Session_State['Supreme_CA']):
            grp.LoadMyInfo(ct()+'[SSL/TLS] [INFO] Recived Valid Server Certificate')
        else:
            grp.LoadMyInfo(ct()+'[SSL/TLS] [WARNING] Recived Invalid Server Certificate')
            return

        #Client Key Exchange
        #Compute client pre master secret
        Session_State['DHE_Params']['Client_Pre_Master_Secret'] = str(pow(int(Session_State['DHE_Params']['Common_Base']), int(Session_State['DHE_Params']['Client_Random']), int(Session_State['DHE_Params']['Common_Z'])))
        #Send Client Key Exchange
        CKE = ssl.Key_Exchange_Encode(Session_State, target = 'client')
        sock.send(CKE.encode())
        grp.LoadMyInfo(ct()+'[SSL/TLS] [INFO] Client Key Exchange send')

        #Server Key Exchange
        SKE = sock.recv(8192).decode()
        Session_State = ssl.key_Exchange_Decode(SKE, Session_State)
        grp.LoadMyInfo(ct()+'[SSL/TLS] [INFO] Recived Server Key Exchange')

        #Client Final Hash
        Session_State['Client_Final_Hash'] = ssl.HMAC_SHA1(Session_State)
        CF = ssl.Finish_Encode(Session_State, Target = 'client')
        sock.send(CF.encode())
        grp.LoadMyInfo(ct()+'[SSL/TLS] [INFO] Client Final Hash send')

        #Server Final Hash
        SF = sock.recv(8192).decode()
        Session_State = ssl.Finish_Decode(SF, Session_State)
        grp.LoadMyInfo(ct()+'[SSL/TLS] [INFO] Recived Server Final Hash')
    except ConnectionResetError:
        grp.LoadMyInfo(ct()+'[SSL/TLS][WARNING] No renegotiation')
        return    

    #Final Hash Checking
    if Session_State['Server_Final_Hash'] == Session_State['Client_Final_Hash']:
        grp.LoadMyInfo(ct()+'[SSL/TLS] [INFO] Hash checking successfully terminated')
    else:
        grp.LoadMyInfo(ct()+'[SSL/TLS] [ERROR] Hash checking failed')
        return

    #Compute Master secret
    Session_State['DHE_Params'] ['Master_Secret'] = str(pow(int(Session_State['DHE_Params']['Server_Pre_Master_Secret']), int(Session_State['DHE_Params']['Client_Random']), int(Session_State['DHE_Params']['Common_Z'])))

    #Password
    Password = sha1(str(Session_State['DHE_Params']['Master_Secret']).encode()).hexdigest()
    grp.LoadMyInfo(ct()+'[SSL/TLS] [INFO] Handshake successfully ended')

    return str(Password)

def socket_setup(server_info):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_name, port))
    except ConnectionRefusedError:
        grp.LoadMyInfo(ct()+'[SOCKET] [ERROR] Unable to establish connection')
        return False
    server_info['sock'] = client_socket
    return True

def server_init(server_info):
    server_info['sock'].send(host_name.encode())

    server_info['password'] = Handshake(server_info['sock'])
    if server_info['password'] == None:
        return
    
    start_new_thread(data.recive, (server_info, ))
    start_new_thread(data.loader, (server_info, ))

#MAIN

def main():
    if socket_setup(server_info):
        start_new_thread(server_init, (server_info, ))
    grp.M_loop()

main()
