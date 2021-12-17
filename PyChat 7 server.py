#Alessandro Canevaro
#Server for PyChat® 7
#18/FEB/2016

#Libraries
import socket
from time import strftime, sleep
from urllib.request import urlopen
from _thread import start_new_thread
from platform import machine, platform, processor
from hashlib import sha1

from Aes_Lib import AES
from Rsa_Lib import RSA, Prime
from SSL_TLS_Lib import MAC
from SSL_TLS_Lib import SSL_TLS as ssl

aes = AES()

#Constant

host_name = socket.gethostname() #Returns the name of the machine.
port = 8888                      #Common port used for PyChat®.
connection_number = 10           #Number of connections that the server can handle simultaneously.

Operating_State = {'DEBUG':True, 'MAC':True, 'ENCRYPTION':True} 

File = {'Server_Kpu': 'Server_Pubblic_Key.doc', 'Server_Kpr': 'Server_Private_Key.doc',
        'Server_CA': 'Server_CA.doc', 'Supreme_CA': 'CA.doc'}

Error = {'reciver':'[HTTP][INFO] Unknow reciver',
         'disconnected':'[SOCKET][INFO] Client has disconnected (data_recive)'}

Connection = {}

#Functions

ct = lambda:'['+strftime('%X')+']' #Returns the current time

class data:
    '''Data manipulation functions'''

    def check_in(Mess, name):
        '''provides encryption, Mac creation and encoding data if request in OPS'''
        if Operating_State['ENCRYPTION']:
            Mess = aes.encode4(Mess)
            Mess = aes.encrypt(Mess, Connection[name][1])
        if Operating_State['MAC']:
            Mess = MAC.Mac_Creator(Mess)
        Mess = Mess.encode()
        return Mess

    def check_out(Mess, name):
        '''provides decryption, Mac checking and decoding data if request in OPS'''
        Mess = Mess.decode()
        if Operating_State['MAC']:
            Mess = MAC.Mac_Check(Mess)
        if Operating_State['ENCRYPTION']:
            Mess = aes.decrypt(Mess, Connection[name][1])
            Mess = aes.decode4(Mess)
        return Mess

    def send(Mess, name): #error managing
        '''Send data to the 'name' socket'''
        Mess = data.check_in(Mess, name)
        try:
            Connection[name][0].send(Mess)
        except ConnectionResetError:
            print(ct()+'[SERVER][WARNING] Unable to send message')

    def recive(name): #error managing
        '''Function to thread'''
        while True:
            try:
                Mess = Connection[name][0].recv(6144)
                Mess = data.check_out(Mess, name)
                data.manager(Mess)
            except ConnectionResetError:
                print(ct()+Error['disconnected'])
                break

    def manager(Mess):
        name = Mess.split('&£&')
        if name[0] in Connection:
            data.send(Mess, name[0])
        else:
            print(ct()+Error['reciver'])
        
def Handshake(sock):
    '''ssl/tls handshake'''

    print(ct()+'[SSL/TLS][INFO] Handshake started')
    
    Session_State = {'Server_Kpu': RSA.Read_Key(File['Server_Kpu']), 'Client_Kpu': None,
                     'Server_Kpr': RSA.Read_Key(File['Server_Kpr']), 'Session_ID': None, 
                     'Server_CA': ssl.Import_Certificate(File['Server_CA']),
                     'Supreme_CA': ssl.Import_Certificate(File['Supreme_CA']),
                     'DHE_Params': 
                     {'Common_Base': None, 'Common_Z': Prime.randprime(10**500, 10**510),
                      'Server_Random': Prime.randprime(10**300, 10**310),
                      'Client_Pre_Master_Secret': None, 'Server_Pre_Master_Secret': None, 'Master_Secret': None}, 
                     'Client_Final_Hash': None, 'Server_Final_Hash': None}

    print(ct()+'[SSL/TLS][INFO] Session_State ready')

    try:
        #Client Hello Message
        CHM = sock.recv(8192).decode()
        Session_State = ssl.ClientHelloMessage_Decode(Session_State, CHM)
        print(ct()+'[SSL/TLS][INFO] Recived Client Hello Message')

        ##ID
        #if Session_State['Session_ID'] == 'None':
        #    Session_State['Session_ID'] = ssl.ID()
        #else:
        #    logged_ID = ssl.ID_Import()
        #    if Session_State['Session_ID'] in logged_ID:
        #        return str(logged_ID[Session_State['Session_ID']]) #id psw

        #Server Hello Message
        SHM = ssl.ServerHelloMessage_Encode(Session_State)
        sock.send(SHM.encode())
        print(ct()+'[SSL/TLS][INFO] Server Hello Message send')

        #Client Certificate
        CC = sock.recv(8192).decode()
        Client_CA = ssl.Certificate_Decode(CC)
        if ssl.Validate_Certificate(Client_CA, Session_State['Supreme_CA']):
            print(ct()+'[SSL/TLS][INFO] Recived Valid Client Certificate')
        else:
            print(ct()+'[SSL/TLS][WARNING] Recived Invalid Client Certificate')
            return

        #Server Certificate
        SC = ssl.Certificate_Encode(Session_State['Server_CA'])
        sock.send(SC.encode())
        print(ct()+'[SSL/TLS][INFO] Server Certificate send')

        #Client Key Exchange
        CKE = sock.recv(8192).decode()
        Session_State = ssl.key_Exchange_Decode(CKE, Session_State)
        print(ct()+'[SSL/TLS][INFO] Recived Client Key Exchange')

        #Server Key Exchange
        #Compute Server pre master secret
        Session_State['DHE_Params']['Server_Pre_Master_Secret'] = str(pow(int(Session_State['DHE_Params']['Common_Base']), int(Session_State['DHE_Params']['Server_Random']), int(Session_State['DHE_Params']['Common_Z'])))
        #Send Server Key Exchange
        SKE = ssl.Key_Exchange_Encode(Session_State, target = 'server')
        sock.send(SKE.encode())
        print(ct()+'[SSL/TLS][INFO] Server Key Exchange send')

        #Client Final Hash
        CF = sock.recv(8192).decode()
        Session_State = ssl.Finish_Decode(CF, Session_State)
        print(ct()+'[SSL/TLS][INFO] Recived Client Final Hash')

        #Server Final Hash
        Session_State['Server_Final_Hash'] = ssl.HMAC_SHA1(Session_State)
        SF = ssl.Finish_Encode(Session_State, Target = 'server')
        sock.send(SF.encode())
        print(ct()+'[SSL/TLS][INFO] Server Final Hash send')
    except ConnectionResetError:
        print(ct()+'[SSL/TLS][WARNING] No renegotiation')
        return

    #Final Hash Checking
    if Session_State['Server_Final_Hash'] == Session_State['Client_Final_Hash']:
        print(ct()+'[SSL/TLS][INFO] Hash checking successfully terminated')
    else:
        print(ct()+'[SSL/TLS][ERROR] Hash checking failed')
        return

    #Compute Master secret
    Session_State['DHE_Params'] ['Master_Secret'] = str(pow(int(Session_State['DHE_Params'] ['Client_Pre_Master_Secret']), int(Session_State['DHE_Params']['Server_Random']), int(Session_State['DHE_Params']['Common_Z'])))

    #Password
    Password = sha1(str(Session_State['DHE_Params']['Master_Secret']).encode()).hexdigest()
    print(ct()+'[SSL/TLS][INFO] Handshake successfully ended', Password)

    return str(Password)

def socket_setup():
    '''Socket Creation, binding and listening. Ip retriving.'''
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    external_ip = urlopen('http://ip.42.pl/raw').read().decode()
    local_ip = socket.gethostbyname(host_name)
    print('LOCAL IP:', local_ip, '   EXTERNAL IP:', external_ip, '\n')

    server_socket.bind((host_name, port))
    server_socket.listen(connection_number)

    return server_socket

def online():
    '''Send list of online client'''
    template = 'Server&£&[COMMAND]&£&Server_Conn&£&'
    c = ''
    for i in Connection:
        c += i+'&&&'
    for conn in Connection:
        data.send(template+c, conn)
    print(ct()+'[SOCKET][INFO] Connection list updated')

def client_init(sock):
    name = sock.recv(1024).decode()
    print('\n'+ct()+'[SOCKET][INFO]',name,'is now connected')
    psw = Handshake(sock)
    if psw == None:
        return
    Connection[name] = [sock]
    Connection[name].append(psw)
    online()

    data.recive(name)

    #remove connection...
    del Connection[name]
    online()

#MAIN
    
def main():
    print('PyChat® 7\n')
    print('Server running on', platform())
    print('PROCESSOR:', processor(), '('+machine()+')')
    print('HOST:', host_name, '  PORT:', port, '  CONNECTIONS:', connection_number)
    print('OPERATING STATE: DEBUG =' ,Operating_State['DEBUG'], '  MAC =',
          Operating_State['MAC'], '  ENCRYPTION =',Operating_State['ENCRYPTION'])
    server_socket = socket_setup()
    print(ct()+'[SERVER][INFO] Server listening...')
    while True:
        client_conn, __ = server_socket.accept()
        start_new_thread(client_init, (client_conn,))

main()
