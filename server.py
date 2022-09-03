import threading
import socket
import database
import bcrypt
from datetime import datetime

# Defining constants.
HEADER = 64
PORT = 8080 
HOST = socket.gethostbyname(socket.gethostname())
addr = (HOST,PORT) # .bind method binds the address to our server TODO FIX TO CAPITALS
active_users = {}

#Creating & Binding the server 
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(addr)
server.listen()

def send_user_msg(user: socket, msg: str):
    """This function send a message through a socket connection to a user.

    Args:
        user (socket): The socket connection to send the message to.
        msg (str): The message to be sent.
    """
    
    msg_length = len(msg)
    send_msg_length = str(msg_length).encode()
    send_msg_length += b' ' * (HEADER - len(send_msg_length))
    user.send(send_msg_length)
    user.send(msg.encode())


def broadcast(msg: str):
    """This function sends a message to all the connected users.
    Args:
        msg (str): The message to be sent.
    """
    
    for username in active_users:
        if active_users[username][1]:
            send_user_msg(active_users[username][0][0], msg)
            
            
            
def get_help(username: str):
    """This function give the user a description of the chat_room functionality.
    Args:
        username (str): The user to send the help message to.
    """
    
    help_msg = """ 
*** chat_room assistant ***
    - To get help type: /help
    - To leave the chat type: /quit
    - To change status to busy type: /busy
    - To change status to active type: /active
    - To see who is connected to the chat type: /connected
    - To send a private message to a user type: /private <@username> <your message>
    - To ping a user type: /ping <username>
    """
    send_user_msg(active_users[username][0][0], help_msg)
    

def quit_chat(username: str):
    """This function helps a user to quit the chat_room
    Args:
        username (str): The user that wants to quit the chat_room"""
        
    send_user_msg(active_users[username][0][0], 'You have disconnected from the chat_room.')
    send_user_msg(active_users[username][0][0], 'DISCONNECTING')
    broadcast(f"[SERVER] - {username} has left the chat_room.")
    

def get_all_connected(username: str):
    """This function give the user a list of all active connected users.
       return string with all the active connected users.
    """
    active_users_list = str(list(active_users.keys()))
    print(active_users_list)
    send_user_msg(active_users[username][0][0], active_users_list)
   
    
def set_busy(username: str):
    """ This function sets a user status to busy i.e the user can't receive messages.

    Args:
        username (str): The user to set as busy.
    """
    active_users[username][1] = False
    broadcast(f"[SERVER] - {username} is busy and won't receive messages.")


def set_active(username: str):
    """ This function sets a user status to active i.e the user can receive messages.

    Args:
        username (str): _description_
    """
    broadcast(f"[SERVER] - {username} is active again and can receive messages.")
    active_users[username][1] = True

     
def private_msg(username: str, target_username: str, msg: str):
    """This message sends a private message from username to target_username.

    Args:
        username (str): The sender of the private message.
        target_username (str): The recipient of the private message.
        msg (str): The message to be sent.
    """
    now = datetime.now()
    current_time = now.strftime("%H:%M")
    formated_msg = f"[{current_time}] [PRIVATE] {username}: {msg}"
    if (target_username in active_users.keys()):
        if active_users[target_username][1] == True:
            send_user_msg(active_users[target_username][0][0], formated_msg)
        else:
            send_user_msg(active_users[username][0][0], f"[SERVER] - {target_username} is busy and won't receive your messages.")
    else: 
        send_user_msg(active_users[username][0][0], f"[SERVER] - {target_username} is not connected.")

    
def ping(username: str, target_username: str, msg: str):
    pass


def ban(username: str, target_username: str):
    """This function lets an admin to ban a user from the chat_room.
    Args:
        username (str): The admin's username.
        target_username (str): The username to be banned.
    """
    if database.get_username_auth_lvl(username) == 1:
        send_user_msg(active_users[target_username][0][0], "You have been banned from the chat_room.")
        send_user_msg(active_users[target_username][0][0], "DISCONNECTING")
        database.ban_user(target_username)
        broadcast(f"[SERVER] - {target_username} has been banned from the chat_room.")
    else: 
        send_user_msg(active_users[username][0][0], "Only an admin can ban users.") 
        
def lift_ban(username: str, target_username: str):
    """This function let's an admin to lift a ban from a user.
    Args:
        username (str): The admin's username.
        target_username (str): The username to lift the ban from.
    """
    if database.get_username_auth_lvl(username) ==1:
        database.set_auth_lvl(target_username, 0)
        send_user_msg(active_users[username][0][0], f"[SERVER] - {target_username} can now login to the chat_room.")
    else:
        send_user_msg(active_users[username][0][0], "Only an admin can lift a ban.")
        
        
def kick(username: str, target_username: str):
    """This function lets an admin to kick a user from the chat_room.
    Args:
        username (str): The admin's username.
        target_username (str): The username to be kicked.
    """
    if database.get_username_auth_lvl(username) == 1:
        send_user_msg(active_users[target_username][0][0], "You have been kicked from the chat_room by an admin.")
        send_user_msg(active_users[target_username][0][0], "DISCONNECTING")
        broadcast(f"[SERVER] - {target_username} has been kicked from the chat_room.")
    else: 
        send_user_msg(active_users[username][0][0], "Only an admin can kick users.")    
        
        
def encrypt_pass(password: bytes):
    """This function encrypts a password.

    Args:
        password (bytes): The password to be encrypted.

    Returns:
        str: The encrypted password as a string.
    """
    mySalt = bcrypt.gensalt()
    hash = bcrypt.hashpw(password, mySalt)
    return hash

def add_active_user(user: socket, username: str):
    """This function adds an active user to the active_users dictionary.

    Args:
        user (socket): The socket of the username.
        username (str): The username which acts as a key in the dictionary.
    """
    active_users[username] = [(user,), True]
    

keywords =['/private', '/quit', '/connected', '/help', '/busy', '/active', '/ping', '/ban', '/lift_ban', '/kick']
keywords_functions = {
    "help": get_help,
    "quit": quit_chat,
    "connected": get_all_connected,
    "private": private_msg,
    "busy": set_busy,
    "active": set_active,
    "ping": ping, 
    "ban": ban,
    "lift_ban": lift_ban, 
    "kick": kick,
}


def login_user(user: socket):
    """This function handles the login of a user to the chat_room.

    Args:
        user (socket): The socket connection of the user.

    Returns:
        bool: A status of connection. True if successfuly connected else False.
        str: The user's username.
    """
    send_user_msg(user, "Please enter your username: " )
    msg_length = user.recv(HEADER).decode()
    if msg_length:
        msg_length = int(msg_length)
        username = user.recv(msg_length).decode()
        msg_length = None
    send_user_msg(user, "Please enter your password: ")
    
    msg_length = user.recv(HEADER).decode()
    if msg_length:
        msg_length = int(msg_length)
        password = user.recv(msg_length).decode()
    correct_credentials = database.verify_user_pass(username, password)
    if database.get_username_auth_lvl(username) == 999:
        send_user_msg(user, "This user is banned from the chat.")
        send_user_msg(user, 'CONNECTION REFUSED')
        return False, username
    elif (correct_credentials):
        send_user_msg(user, "CONNECTION GRANTED")
        print(f"[SERVER] - {username} has connected to the chat")
        return True, username
    else:
        send_user_msg(user, "[SERVER] - username or password are incorrect, please try again.")
        send_user_msg(user, 'CONNECTION REFUSED')
        return False, username
    
    
def signup_user(user: socket):
    """This function handles the sign up of a user to the chat_room.

    Args:
        user (socket): The socket connection of the user.

    Returns:
        bool: A status of connection. True if successfuly signed up else False.
        str: The user's username.
    """
    send_user_msg(user,"Please choose a username: " )
    msg_length = user.recv(HEADER).decode()
    if msg_length:
        msg_length = int(msg_length)
        username = user.recv(msg_length).decode()
        msg_length = None
    send_user_msg(user, "Please choose a password: ")    
    msg_length = user.recv(HEADER).decode()
    msg_length = int(msg_length)
    if msg_length:
        password = user.recv(msg_length) # Leave password in byte sequence.
    
    if (not (database.username_is_taken(username))):
        hashedPass = encrypt_pass(password)
        if username == 'admin':
            database.add_user(username, hashedPass,1)
        else:
            database.add_user(username, hashedPass, 0)
            print(f"[SERVER] - {username} signed up successfuly")
            send_user_msg(user, 'CONNECTION GRANTED')
            return True, username
    else:
        send_user_msg(user, "[SERVER] - This username already exists in our database, if it's you type 1 to login.")
        send_user_msg(user, 'CONNECTION REFUSED')
        return False, username
    
    
def handle_user(username: str):
    """This function handles the connection of a user to the chat during the
       time that the user is connected to the chat_room.

    Args:
        username (str): The user that is connected to the chat_room.
    """
    connected: bool = True
    user: socket = active_users[username][0][0] 
    while connected:
        try: 
            msg_length = user.recv(HEADER).decode()
            if msg_length:
                msg_length = int(msg_length)
                msg: str = user.recv(msg_length).decode()
            # This code block analyze the msg received from the user to check if the user used
            # a special command - if so it calls to the appropriate function.
            check_for_special_cmd: list = [ele for ele in keywords if (ele in msg)]
            special_cmd: bool = bool(check_for_special_cmd)
            if special_cmd:
                command_to_exec = check_for_special_cmd[0][1:]
                if command_to_exec in ["quit", "help", "busy", "active", "connected"]:
                    keywords_functions[command_to_exec](username)
                elif command_to_exec in ["ping", "private"]:
                    special_char_ind = msg.find('@')
                    if special_char_ind >= 0:
                        target_username = msg[special_char_ind+1:].split(" ", 1)[0]
                        msg = msg[special_char_ind+1:].split(" ", 1)[1]
                        keywords_functions[command_to_exec](username, target_username, msg)
                    else:
                        send_user_msg(user, "Incorrect usage of command. type /help to see how to execute special commands.")
                elif (command_to_exec in ['ban', 'kick', 'lift_ban']):
                    special_char_ind = msg.find('@')
                    if special_char_ind >= 0:
                        target_username = msg[special_char_ind+1:].split(" ", 1)[0]
                        if (command_to_exec in ['ban', 'kick']):
                            if target_username in active_users.keys():
                                keywords_functions[command_to_exec](username, target_username)
                            else:
                                send_user_msg(user, f"{target_username} is not connected.\nYou can ban or kick only connected users.")
                        elif command_to_exec in ['lift_ban']:
                            if database.username_is_taken:
                                keywords_functions[command_to_exec](username,target_username)
                            else:
                                send_user_msg(active_users[username][0][0], f"[SERVER] - {target_username} doesn't exist.")
                    else: 
                        send_user_msg(user, "Incorrect usage of command. type /help to see how to execute special commands.")
                 
            else:
                now = datetime.now()
                current_time = now.strftime("%H:%M")
                broadcast(f"[{current_time}] {username}: {msg}")         
        except:
            user.close()
            active_users.pop(username)
            connected = False
            

def receive():
    """This function handles the connection a users to the server that is receiving 
       new logins or sign ups to the chat room.
    """
    while True:
        user, addr = server.accept()
        send_user_msg(user, 'Welcome to the CHAT_ROOM!\nTo login type 1\nTo Sign Up type 2')
        login_or_signup = 0
        msg_length = user.recv(HEADER).decode()
        if msg_length:
            msg_length = int(msg_length)
            login_or_signup = user.recv(msg_length).decode()
        if login_or_signup == '1':
            connected, username = login_user(user)
        elif login_or_signup == '2':
            connected, username = signup_user(user)
        else:
            send_user_msg(user, 'Something went wrong!')
            user.close()
            continue
        
        if connected:
            broadcast(f"[SERVER] - {username} has entered the chat_room.")
            add_active_user(user, username)
            thread = threading.Thread(target=handle_user, args=(username,))
            thread.start()
        else: 
            continue
        
            
print("[SERVER] - waiting for new connections...")
receive()
