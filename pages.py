# Dependencies
import os
import helper
import base64
import hashlib
import sqlite3
import getpass
import validators
from prettytable import PrettyTable
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Connect with the databse
conn = sqlite3.connect("user.db")
cursor = conn.cursor()


# Register page
def register():
    print("[type '//c' to cancel]")

    # Get user input
    while True:
        username_input = input("username\t: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(username_input):
            return

        if username_input.isalnum():
            break
        helper.warning("invalid username")
    
    while True:
        email_input = input("email\t\t: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(email_input):
            return

        if helper.emailIsValid(email_input):
            break
        helper.warning("invalid email")

    while True:
        password_input = input("master password\t: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(password_input):
            return

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
    helper.warning("successfully made account")

    while True:
        user_input = input("\nwould you like to login/exit?(l/e): ").strip()

        if user_input in ["l", "login"]:
            return
        
        elif user_input in ["e", "exit"]:
            quit()


# Login page
def login():
    # Get users hashed password
    data = cursor.execute("SELECT * FROM user").fetchall()[0]
    email = data[2]
    master_password_hash = data[3]
    salt = data[4]

    while True:
        master_password_input = getpass.getpass("master password: ").strip()
        if hashlib.sha256(master_password_input.encode()).hexdigest() == master_password_hash:
            helper.success("welcome :)")
            helper.success("type 'help' for help")

            # Password is the unhashed master password + email
            password = (master_password_input + email).encode("utf8")
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=390000
            )

            key = base64.urlsafe_b64encode(kdf.derive(password)) # Key is based on user unhashed master password input
            return key


# Display data in a formatted way
def displayCards(key):
    fetched_data = cursor.execute("SELECT id, url, website, username, email, password FROM savings").fetchall()

    # Return warning if we get nothing
    if len(fetched_data) < 1:
        helper.warning("no current data")
        return

    # Prints user data in a table
    helper.printTable(fetched_data, key)


# Make new card
def newCard(key):

    # Get user input
    # Get valid url
    while True:
        url_input = input("url\t\t: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(url_input):
            return

        elif validators.url(url_input):
            break

        helper.warning("invalid url")

    # Get website name
    while True:
        website_input = input("website\t\t: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(website_input):
            return

        elif " " not in website_input and website_input:
            break

        helper.warning("invalid website")

    # Get username
    while True:
        username_input = input("username\t: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(username_input):
            return
        
        elif username_input:
            break

    # Get valid email
    while True:
        email_input = input("email\t\t: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(email_input):
            return

        elif email_input == "email":
            email_input = cursor.execute("SELECT email FROM user").fetchall()[0][0]
            conn.commit()
            break

        elif helper.emailIsValid(email_input):
            break

        helper.warning("invalid email")

    # Get valid password/generate password
    while True:
        password_input = input("password\t: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(password_input):
            return

        # See if there is anything on the input field
        elif password_input:

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
            url_token = fernet.encrypt(url_input.encode()).decode()
            website_token = fernet.encrypt(website_input.encode()).decode()
            username_token = fernet.encrypt(username_input.encode()).decode()
            email_token = fernet.encrypt(email_input.encode()).decode()
            password_input_hashtoken = fernet.encrypt(password_input.encode()).decode()

            # Insert data into the table
            cursor.execute("INSERT INTO savings (url, website, username, email, password) VALUES(?, ?, ?, ?, ?)", (url_token, website_token, username_token, email_token, password_input_hashtoken))
            conn.commit()
            helper.success("successfully inserted into table")
            return

        elif user_confirmation in ["n", "no"]:
            helper.warning("cancelled")
            return

        helper.warning("invalid input")


# Search data
def search(key):

    while True:
        user_input = input("search by website: ").strip()

        # See if the user wants to cancel
        if helper.wantsToExitInpuField(user_input):
            return

        # Check if the user input is valid for parsing
        elif user_input:
            break
            
        helper.warning("invalid input")

    # Query the database
    fetched_data = helper.searchTable(key, user_input)

    if fetched_data == None or len(fetched_data) < 1:
        helper.warning("no matching data")
        return

    # Prints search results
    helper.printTable(fetched_data, key)


# Delete data
def delete(key):

    while True:
        user_input = input("delete by website: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(user_input):
            return

        # Check if the user input is valid for parsing
        elif user_input:
            break
            
        helper.warning("invalid input")

    # Query the database
    fetched_data = helper.searchTable(key, user_input)

    if fetched_data == None or len(fetched_data) < 1:
        helper.warning("no matching data")
        return

    print("\n  Data you wish to delete:\n")

    # Prints search results
    helper.printTable(fetched_data, key)

    # Ask the user if they would like to continue
    while True:
        user_confirmation = input("proceed?(y/n): ").strip().lower()

        # If the user wishes to continue
        if user_confirmation in ["y", "yes"]:

            # Delete data
            helper.deleteData(fetched_data)
            helper.success("successfully deleted from table")
            return

        # If the user wants to cancel
        elif user_confirmation in ["n", "no"]:
            helper.warning("cancelled")
            return
        
        helper.warning("invalid input")


# Update data
def update(key):

    while True:
        user_input = input("update by id: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(user_input):
            return

        # Check if the user input is valid for parsing
        elif user_input and user_input.isdigit():
            break
            
        helper.warning("invalid input")

    # Query the database
    fetched_data = cursor.execute("SELECT id, url, website, username, email, password FROM savings WHERE id=?", (user_input,)).fetchall()

    if fetched_data == None or len(fetched_data) < 1:
        helper.warning("no matching data")
        return

    # Prints search results
    helper.printTable(fetched_data, key)

    # Get user input for which column to update
    while True:
        update_column = input("column: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(update_column):
            return

        elif update_column.lower() in ["url", "website", "username", "email", "password"]:
            break

        helper.warning("invalid column")

    # Get user input for what to update the column with the id to
    while True:
        update_item = input("set to: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(user_input):
            return

        elif helper.validUpdateItem(update_column, update_item):
            break

        helper.warning("invalid input")


    # Ask the user if they would like to continue
    while True:
        user_confirmation = input("proceed?(y/n): ").strip().lower()

        # If the user wishes to continue
        if user_confirmation in ["y", "yes"]:

            # Update data
            helper.updateData(update_column, update_item, fetched_data[0][0], key)
            helper.success("successfully updated table")
            return

        # If the user wants to cancel
        elif user_confirmation in ["n", "no"]:
            helper.warning("cancelled")
            return
        
        helper.warning("invalid input")


# Prints all the commands
def help():
    table = PrettyTable()
    table.add_row(["'help'              help page"])
    table.add_row(["'/display'          displays saved data"])
    table.add_row(["'/new '             saves new data"])
    table.add_row(["'/search'           searches data"])
    table.add_row(["'/delete'           deletes data"])
    table.add_row(["'/update'           updates data"])
    table.add_row(["'clear'             clears the screen"])
    table.add_row(["'exit'/'quit'       kills the program"])
    table.add_row(["'//c'                 exists out of input fields"])
    table.align = "l"
    table.header = False
    print(table)