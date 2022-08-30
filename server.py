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
    pass

def quit_chat():
    pass

def get_all_connected():
    pass
def send_private_message():
    pass

def set_busy(status: bool):
    pass

def ping_username():
    pass

def ban_username():
    pass

def kick_username():
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
    

keywords =['/private', '/quit', '/connected', '/help', '/busy','/active', '@', '/ban', '/kick']
keywords_functions = {
    "get_help": get_help,
    "quit_chat": quit_chat,
    "get_all_connected": get_all_connected,
    "send_private_message": send_private_message,
    "set_afk": set_busy,
    "ping_username": ping_username, 
    "ban_username": ban_username, 
    "kick_username": kick_username,
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
    while True:
        try: 
            msg: str = user.recv(1024).decode()
            check_for_special_cmd: list = [ele for ele in keywords if (ele in msg)]
            special_cmd: bool = bool(check_for_special_cmd) 
            if special_cmd:
                pass
            else:
                broadcast(f"{username}: {msg}")         
        except:
            user.close()
            active_users.pop(username)
            break
            

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
