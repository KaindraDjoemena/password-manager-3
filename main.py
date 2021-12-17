# Dependencies
import os
import helper
import base64
import hashlib
import sqlite3
import getpass
import validators
from prettytable import PrettyTable
from prettytable import NONE
from prettytable import HEADER
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Connect with the databse
conn = sqlite3.connect("user.db")
cursor = conn.cursor()


def register():

    # Get user input
    while True:
        username_input = input("username\t: ").strip()
        if username_input.isalnum():
            break
        helper.warning("invalid username")
    
    while True:
        email_input = input("email\t\t: ").strip()
        if helper.emailIsValid(email_input):
            break
        helper.warning("invalid email")

    while True:
        password_input = input("master password\t: ").strip()
        if helper.passwordIsValid(password_input):
            break
        
        # Check for errors in the password input
        if len(password_input) < 9:
            helper.warning("password must be at least 9 chars long")
        else:
            helper.warning("invalid password")

    # Make tables
    # User table
    cursor.execute("""CREATE TABLE user (
        id INTEGER PRIMARY KEY,
        username TEXT,
        email TEXT,
        master_password TEXT,
        salt BLOB,
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

    # Savings table
    cursor.execute("""CREATE TABLE savings (
        id INTEGER PRIMARY KEY,
        url TEXT,
        website TEXT,
        username TEXT,
        email TEXT,
        password TEXT,
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

    # Hash password
    password_input_hash = hashlib.sha256(password_input.encode()).hexdigest()
    salt = os.urandom(16)

    # Insert data into the table
    cursor.execute("INSERT INTO user (username, email, master_password, salt) VALUES(?, ?, ?, ?)", (username_input, email_input, password_input_hash, salt))
    conn.commit()


def login():
    # Get users hashed password
    data = cursor.execute("SELECT * FROM user").fetchall()[0]
    email = data[2]
    master_password_hash = data[3]
    salt = data[4]

    while True:
        master_password_input = getpass.getpass("master password: ").strip()
        if hashlib.sha256(master_password_input.encode()).hexdigest() == master_password_hash:
            print("     welcome :)")

            # Password is the unhashed master password + email
            password = (master_password_input + email).encode("utf8")
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=390000
            )

            key = base64.urlsafe_b64encode(kdf.derive(password)) # Key is based on user unhashed master password input
            main(key)


# Main function
def main(key):
    while True:
        while True:
            user_input = input(">>").strip().lower()
            if helper.isValid(user_input):
                break
            helper.warning("invalid input")
        
        # Clears terminal
        if user_input == "clear":
            os.system("cls")

        # Quitting the program
        elif user_input in ["quit", "exit"]:
            conn.commit()
            conn.close()
            exit()

        # Displays user data
        elif user_input == "display":
            displayCards(key)

        # Makes new cards
        elif user_input == "new":
            newCard(key)


def displayCards(key):
    fetched_data = cursor.execute("SELECT url, website, username, email, password_hash FROM savings").fetchall()

    # Return warning if we get nothing
    if len(fetched_data) < 1:
        helper.warning("no current data")
        return

    # Print the data
    table = PrettyTable()
    table.field_names = ["URL", "Website", "Username", "Email", "Password"]
    fernet = Fernet(key)
    for data in fetched_data:
        table.add_row([
            fernet.decrypt(data[0].encode()).decode(),
            fernet.decrypt(data[1].encode()).decode(),
            fernet.decrypt(data[2].encode()).decode(),
            fernet.decrypt(data[3].encode()).decode(),
            fernet.decrypt(data[4].encode()).decode()
        ])

    # Formatting the table
    table.left_padding_width = 1
    table.vrules = NONE
    table.hrules = HEADER
    print(table)
    print()



def newCard(key):

    # Get user input
    # Get valid url
    while True:
        url_input = input("url\t\t: ").strip()
        if validators.url(url_input):
            break
        helper.warning("invalid url")

    # Get website name
    while True:
        website_input = input("website\t\t: ").strip()
        if " " not in website_input:
            break
        helper.warning("invalid website")

    # Get username
    while True:
        username_input = input("username\t: ").strip()
        if username_input:
            break

    # Get valid email
    while True:
        email_input = input("email\t\t: ").strip()
        if email_input == "email":
            email_input = cursor.execute("SELECT email FROM user").fetchall()[0][0]
            break

        elif helper.emailIsValid(email_input):
            break

        helper.warning("invalid email")

    # Get valid password/generate password
    while True:
        password_input = input("password\t: ").strip()

        # See if there is anything on the input field
        if password_input:

            split_password_input = password_input.split()
            if split_password_input[0] == "random":
                # See if the command is only 'random'
                if len(split_password_input) == 1:
                    password_input = helper.generatePassword()

                # See if the command is 'random' with the random password length
                elif " " in password_input and len(split_password_input) == 2 and split_password_input[1].isdigit():
                    int(split_password_input[1])
                    password_input = helper.generatePassword(int(split_password_input[1]))

        # Ssee if it's longer than 8 chars or not
        if helper.passwordIsValid(password_input):
            break

        # Check for error in the password input
        if len(password_input) < 9:
            helper.warning("password must be at least 9 chars long")
        if " " in password_input:
            helper.warning("invalid password")
        


    # Ask the user if they would like to continue
    while True:
        user_confirmation = input("proceed?(y/n): ").strip().lower()
        if user_confirmation in ["y", "yes"]:

            # Encrypt
            fernet = Fernet(key)
            url_token = fernet.encrypt(url_input.encode("utf8")).decode("utf8")
            website_token = fernet.encrypt(website_input.encode("utf8")).decode("utf8")
            username_token = fernet.encrypt(username_input.encode("utf8")).decode("utf8")
            email_token = fernet.encrypt(email_input.encode("utf8")).decode("utf8")
            password_input_hashtoken = fernet.encrypt(password_input.encode("utf8")).decode("utf8")

            # Insert data into the table
            cursor.execute("INSERT INTO savings (url, website, username, email, password_hash) VALUES(?, ?, ?, ?, ?)", (url_token, website_token, username_token, email_token, password_input_hashtoken))
            conn.commit()
            break

        elif user_confirmation in ["n", "no"]:
            helper.warning("cancelled")
            break



if __name__ == "__main__":
    # Try accessing these tables and see if they exist or not
    try:
        cursor.execute("SELECT * FROM user")
        cursor.execute("SELECT * FROM savings")
    except:
        register()

    login()