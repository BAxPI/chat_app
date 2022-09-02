import sqlite3
import bcrypt


conn = sqlite3.connect('users.db')
c = conn.cursor()

c.execute("""CREATE TABLE IF NOT EXISTS users (
                username TEXT,
                passw TEXT, 
                authorization_lvl INTEGER 
        )""")
    

def add_user(username, passw, authorization_lvl):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT INTO users VALUES (?,?,?)", (username,passw,authorization_lvl))
    conn.commit()
    conn.close()
    

def get_user_id(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT rowid FROM users WHERE username=(?) AND passw=(?)", (username,))
    user_id = c.fetchone()
    conn.close()
    return user_id[0]

def get_username(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE rowid =(?)" ,(user_id,))
    user = c.fetchone()
    username = user[0]
    conn.close()
    return username


def get_username_auth_lvl(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=(?)", (username,))
    user = c.fetchone()
    print(user)
    auth_lvl = user[2]
    conn.close()
    return auth_lvl
    
    
    
def verify_user_pass(username, password): 
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=(?)", (username,))
    user = c.fetchone()
    verified = False
    if (user != None):
        verified = bcrypt.checkpw(password.encode(), user[1])
        if verified:
            print(f"[SERVER] - {username} verified successfuly")
    conn.close()
    if(verified): 
        return True
    return False

def username_is_taken(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=(?)", (username,))
    user = c.fetchone()
    if(user != None):
        return True
    return False



    