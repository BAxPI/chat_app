import threading
import socket
import database
import bcrypt
from datetime import datetime


host = socket.gethostbyname(socket.gethostname())
PORT = 8080 
addr = (host,PORT) # .bind method binds the address to our server

active_users = {}

#Creating & Binding the server 
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(addr)
server.listen()

def broadcast(msg: str):
    for username in active_users:
        if active_users[username][1]:
            active_users[username][0][0].send(msg.encode())
            
            
def get_help(username: str):
    """This function give the user a description of the chat_room functionality
       return string describing app functionality.
    """
    help_msg = """ 
    *** chat_room assistant ***
        - To get help type: /help
        - To leave the chat type: /quit
        - To change status to busy type: /busy
        - To change status to active type: /active
        - To see who is connected to the chat type: /connected
        - To send a private message to a user type: /send_private 
                                                   <@username here> <your message>
        - To ping a user type: /ping <username>
    """
    active_users[username][0][0].send(help_msg.encode())

def quit_chat(username: str):
    """This function helps a user to quit the chat_room"""
    active_users[username][0][0].send('DISCONNECTING'.encode())
    # connected = False
    active_users[username][0][0].close()


def get_all_connected(username: str):
    """This function give the user a list of all active connected users.
       return string with all the active connected users.
    """
    active_users_list = str(list(active_users.keys()))
    print(active_users_list)
    active_users[username][0][0].send((active_users_list).encode())
    
def set_busy(username: str):
    active_users[username][1] = False

def set_active(username: str):
    active_users[username][1] = True
     
def private_msg(username: str, target_username: str, msg: str):
    now = datetime.now()
    current_time = now.strftime("%H:%M")
    active_users[target_username][0][0].send(f"[{current_time}] [PRIVATE] {username}: {msg}".encode())
    
def ping(username: str, target_username: str, msg: str):
    pass

def ban(username: str):
    pass

def kick(username: str, target_username: str):
    active_users[target_username][0][0].send('DISCONNECTING'.encode())
    active_users[target_username][0][0].close()
    # Check if necessary to update active users list.
    


def encrypt_pass(password: bytes) -> str:
    mySalt = bcrypt.gensalt()
    hash = bcrypt.hashpw(password, mySalt)
    return hash

def add_active_user(user: socket, username: str):
    active_users[username] = [(user,), True]
    

keywords =['/private_msg', '/quit', '/connected', '/help', '/busy', '/active', '/ping', '/ban', '/kick']
keywords_functions = {
    "help": get_help,
    "quit": quit_chat,
    "connected": get_all_connected,
    "private_msg": private_msg,
    "busy": set_busy,
    "active": set_active,
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
    password = user.recv(1024) # Leave password in byte sequence.
    
    if (not (database.username_is_taken(username))):
        hashedPass = encrypt_pass(password)
        if username == 'admin':
            database.add_user(username, hashedPass,1)
        else:
            database.add_user(username, hashedPass, 0)
            print(f"[SERVER] - {username} signed up successfuly")
            user.send('CONNECTION GRANTED'.encode())
            return True, username
    else:
        return False, username
    
    
def handle_user(user: socket, username: str):
    connected: bool = True
    while connected:
        try: 
            msg: str = user.recv(1024).decode()
            check_for_special_cmd: list = [ele for ele in keywords if (ele in msg)]
            special_cmd: bool = bool(check_for_special_cmd)
            if special_cmd:
                command_to_exec = check_for_special_cmd[0][1:]
                if command_to_exec in ["quit", "help", "busy", "active", "connected"]:
                    keywords_functions[command_to_exec](username)
                elif command_to_exec in ["ping", "private_msg"]:
                    special_char_ind = msg.find('@')
                    target_username = msg[special_char_ind+1:].split(" ", 1)[0]
                    msg = msg[special_char_ind+1:].split(" ", 1)[1]
                    keywords_functions[command_to_exec](username, target_username, msg)
                elif (command_to_exec in ['ban', 'kick']) and (database.get_username_auth_lvl(username) == 1):
                    special_char_ind = msg.find('@')
                    target_username = msg[special_char_ind+1:].split(" ", 1)[0]
                    keywords_functions[command_to_exec](username, target_username,)
                    
            else:
                now = datetime.now()
                current_time = now.strftime("%H:%M")
                broadcast(f"[{current_time}] {username}: {msg}")         
        except:
            user.close()
            active_users.pop(username)
            connected = False
            

def receive():
    while True:
        user, addr = server.accept()
        user.send('Welcome to the CHAT_ROOM!\nTo login type 1\nTo Sign Up type 2 '.encode())    
        login_or_signup = user.recv(1024).decode()
        if login_or_signup == '1':
            connected, username = login_user(user, addr)
    
        elif login_or_signup == '2':
            connected, username = signup_user(user, addr)
        
        else:
            user.send('Something went wrong!'.encode())
            user.close()
            continue
        
        if connected:
            add_active_user(user, username)
            thread = threading.Thread(target=handle_user, args=(user, username))
            thread.start()
        else: 
            user.send('CONNECTION REFUSED'.encode())
            user.close()
            continue
        
            
print("[SERVER] - waiting for new connections...")
receive()
