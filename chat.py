import threading
import socket
import time

user: socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
host: str = socket.gethostbyname(socket.gethostname())
port: int = 8080
addr: tuple = (host,port)
user.connect(addr)

def loginOrSignup():
    while True:
        msg = user.recv(1024).decode()
        if (msg == 'CONNECTION GRANTED'):
            return True
        elif (msg == 'CONNECTION REFUSED'):
            return False
        else:
            print(msg)
            user_response = input().encode()
            user.send(user_response)

  
def receive():
    print("[USER] - listening to the server now...")
    while True:
        msg = user.recv(1024).decode()
        if msg:
            print(msg)
    
def write():
    print("[SERVER] - You can start chatting")
    while True:
        msg = input().encode()
        user.send(msg)
        
connected = loginOrSignup()  
     
if(connected):
    print("CONNECTED")
    receive_thread = threading.Thread(target=receive)
    receive_thread.start()

    write_thread = threading.Thread(target=write)
    write_thread.start()
else: 
    user.close()
    print("[SERVER] - Connection refused. Please check your username and password.")
    # exit(0)
    
    
