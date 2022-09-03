import threading
import socket

global connected
connected: bool = False

HEADER = 64
HOST: str = socket.gethostbyname(socket.gethostname())
PORT: int = 8080
ADDR: tuple = (HOST,PORT)
user: socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
user.connect(ADDR)


def send_msg(sock: socket, msg: str):
    """This function send a string message through a given socket connection.
       Args:
           sock (socket): The socket to send the message through.
           msg (str): The message to be sent.
    """
    msg_length = len(msg)
    send_msg_length = str(msg_length).encode()
    send_msg_length += b' ' * (HEADER - len(send_msg_length))
    sock.send(send_msg_length)
    sock.send(msg.encode())
    
    
def loginOrSignup():
    """This functions handles the login or sign up of a user to the chat_room
       Returns:
           connected (bool): True if the user connected or signed in successfuly.
                             False if the user could not connect for some reason.
    """
    while True:
        msg_length = user.recv(HEADER).decode()
        if msg_length:
            msg_length = int(msg_length)
            msg = user.recv(msg_length).decode()
            if (msg == 'CONNECTION GRANTED'):
                return True
            elif (msg == 'CONNECTION REFUSED'):
                return False
            else:
                print(msg)
                user_response = input()
                send_msg(user, user_response)
    

connected = loginOrSignup()  


def receive():
    """This function handles the reception of messages from the server."""
    global connected
    while connected:
        msg_length = user.recv(HEADER).decode()
        if msg_length:
            msg_length = int(msg_length)
            msg = user.recv(msg_length).decode()
            if msg == 'DISCONNECTING':
                connected = False
            elif msg:
                print(msg)
    
    
def write():
    """This function handles the sending of messages to the server."""
    global connected
    print("[SERVER] - You can start chatting")
    while connected:
        try:
            msg = input() 
            send_msg(user, msg)
        except:
            print("Couldn't send the message.")
            connected = False
        
     
if(connected):
    receive_thread = threading.Thread(target=receive)
    receive_thread.start()

    write_thread = threading.Thread(target=write)
    write_thread.start()
else: 
    user.close()
    


    
