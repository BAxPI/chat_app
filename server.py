import threading
import socket
import database
import bcrypt

host = socket.gethostbyname(socket.gethostname())
port = 8080 
addr = (host,port) # .bind method binds the address to our server

active_users = {}

#Creating & Binding the server 
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(addr)
server.listen()


def get_help():
    """This function give the user a description of the chat_room functionality
       return string describing app functionality.
    """
    pass

def quit_chat(username: str, user: socket, connected: bool):
    """This function helps a user to quit the chat_room"""
    user.send('DISCONNECTING'.encode())
    connected = False
    user.close()


def get_all_connected():
    """This function give the user a list of all active connected users.
       return string with all the active connected users.
    """
    pass
def private_msg():
    pass

def set_busy(status: bool):
    pass

def ping():
    pass

def ban():
    pass

def kick():
    pass

def broadcast(msg: str):
    for username in active_users:
        if active_users[username][1] == True:
            active_users[username][0][0].send(msg.encode())
            
def encrypt_pass(password: bytes):
    mySalt = bcrypt.gensalt()
    hash = bcrypt.hashpw(password, mySalt)
    return hash

def add_active_user(username, user):
    active_users[username] = [(user,), True]
    

keywords =['/private_msg', '/quit_chat', '/get_all_connected', '/get_help', '/set_busy','/active', 'ping', '/ban', '/kick']
keywords_functions = {
    "get_help": get_help,
    "quit_chat": quit_chat,
    "get_all_connected": get_all_connected,
    "private_msg": private_msg,
    "set_busy": set_busy,
    "ping": ping, 
    "ban": ban, 
    "kick": kick,
}



def login_user(user: socket, adrr: str):
    user.send("Please enter your username: ".encode())
    username = user.recv(1024).decode()
    user.send("Please enter your password: ".encode())
    password = user.recv(1024).decode()
    correct_credentials = database.verify_user_pass(username, password)
    if (correct_credentials):
        user.send('CONNECTION GRANTED'.encode())
        print(f"[SERVER] - {username} has connected to the chat")
        return True, username
    else: 
        return False, username
    


def signup_user(user: socket, addr: str):
    user.send("Please choose a username: ".encode())
    username = user.recv(1024).decode()
    user.send("Please choose a password: ".encode())
    password = user.recv(1024) # Leave password in bytes object
    
    if (not (database.username_is_taken(username))):
        hashedPass = encrypt_pass(password)
        database.add_user(username, hashedPass, 0)
        print(f"[SERVER] - {username} signed up successfuly")
        user.send('CONNECTION GRANTED'.encode())
        return True, username
    else:
        return False, username
    
    
    
def handle_user(user: socket, username: str):
    print(f"[SERVER] - Starting to handle {username}")
    connected: bool = True
    while connected:
        try: 
            msg: str = user.recv(1024).decode()
            check_for_special_cmd: list = [ele for ele in keywords if (ele in msg)]
            special_cmd: bool = bool(check_for_special_cmd)
            if special_cmd:
                command_to_exec = check_for_special_cmd[0][1:]
                print(f"command to exec: {command_to_exec}")
                keywords_functions[command_to_exec](username, user, connected)
            else:
                broadcast(f"{username}: {msg}")         
        except:
            user.close()
            active_users.pop(username)
            connected = False
            

def receive():
    while True:
        user, addr = server.accept()
        user.send('Welcome to the CHAT_ROOM!\nTo login type 1\nTo Sign Up type 2 '.encode())
        loginOrSignup = user.recv(1024).decode()
        if loginOrSignup == '1':
            connected, username = login_user(user, addr)
        
        elif loginOrSignup == '2':
            connected, username = signup_user(user, addr)
        
        else:
            user.send('Something went wrong!'.encode())
            user.close()
            continue
        
        if connected:
            add_active_user(username, user)
            thread = threading.Thread(target=handle_user, args=(user, username))
            thread.start()
        else: 
            user.send('CONNECTION REFUSED'.encode())
            user.close()
            continue
        
            



print("[SERVER] - waiting for new connections...")
receive()
