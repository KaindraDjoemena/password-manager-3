# Dependencies
import os
import helper
import hashlib
import getpass
import pyperclip
from prettytable import PrettyTable
from cryptography.fernet import Fernet


def register(cursor, conn):
    """
    Takes user input to register the user
    When their inputs are all valid, the function make the 'user' and 'savings' table
    The function will also encrypt the data before insertint the user data into the 'user' table
    
    """

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
        master_password_input = input("master password\t: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(master_password_input):
            return

        if helper.passwordIsValid(master_password_input):
            break
        
        # Check for errors in the password input
        if len(master_password_input) < 9:
            helper.warning("password must be at least 9 chars long")
        else:
            helper.warning("invalid password")

    # Ask the user if they would like to continue
    while True:
        print("* BE SURE OF YOUR MASTER PASSWORD *")
        print("* YOU WILL NOT BE ABLE TO CHANGE YOUR MASTER PASSWORD *")
        user_confirmation = input("proceed?(y/n): ").strip().lower()

        # If the user wishes to continue
        if user_confirmation in ["y", "yes"]:
            break

        # If the user wants to cancel
        elif user_confirmation in ["n", "no"]:
            helper.warning("cancelled")
            return
        
        helper.warning("invalid input")

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
    password_input_hash = hashlib.sha256(master_password_input.encode()).hexdigest()
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


def login(cursor):
    """
    Takes the hash of the user's master password input and compares it to the existing master password hash
    After the user logs in, the function generates a key for the encryption from the master password
    
    """

    # Get users hashed password
    data = cursor.execute("SELECT * FROM user").fetchall()[0]
    master_password_hash = data[3]

    while True:
        master_password_input = getpass.getpass("master password: ").strip()
        if hashlib.sha256(master_password_input.encode()).hexdigest() == master_password_hash:
            helper.success("welcome :)")
            print()
            helper.success("type 'help' for help")

            return helper.generateKey(cursor, master_password_input)


def displayCards(cursor, key, ascending=True):
    """
    Displays all the rows in a table format
    
    """

    if ascending:
        fetched_data = cursor.execute("SELECT id, url, website, username, email, password FROM savings").fetchall()

    elif not ascending:
        fetched_data = cursor.execute("SELECT id, url, website, username, email, password FROM savings ORDER BY time DESC").fetchall()

    # Return warning if we get nothing
    if len(fetched_data) < 1:
        helper.warning("no current data")
        return

    # Prints user data in a table
    helper.printTable(fetched_data, key)


def newCard(cursor, conn, key):
    """
    Makes/saves a new card by inputting a url, website name, username, email, and password then encrypting it
    When all the inputted data are valid, the function encrypts all the data before inserting it into the 'savings' table

    """

    # Get user input
    # Get valid url
    while True:
        url_input = input("url\t\t: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(url_input):
            return

        elif helper.validInputs("url", url_input):
            break

        helper.warning("invalid url")

    # Get website name
    while True:
        website_input = input("website\t\t: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(website_input):
            return

        elif helper.validInputs("website", website_input):
            break

        helper.warning("invalid website")

    # Get username
    while True:
        username_input = input("username\t: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(username_input):
            return
        
        elif helper.validInputs("username", username_input):
            break

    # Get valid email
    while True:
        email_input = input("email\t\t: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(email_input):
            return

        elif email_input == "email":
            email_input = cursor.execute("SELECT email FROM user").fetchall()[0][0]
            break

        elif helper.validInputs("email", email_input):
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


def search(cursor, key):
    """
    Prints a row of data by specifying its website column in a table format
    
    """

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
    fetched_data = helper.searchTable(cursor, key, user_input)

    if fetched_data == None or len(fetched_data) < 1:
        helper.warning("no matching data")
        return

    # Prints search results
    helper.printTable(fetched_data, key)


def delete(cursor, conn, key):
    """
    Deletes a row of data by specifying its website column
    
    """

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
    fetched_data = helper.searchTable(cursor, key, user_input)

    if fetched_data == None or len(fetched_data) < 1:
        helper.warning("no matching data")
        return

    print("\n  Data you wish to delete:")

    # Prints search results
    helper.printTable(fetched_data, key)

    # Ask the user if they would like to continue
    while True:
        user_confirmation = input("proceed?(y/n): ").strip().lower()

        # If the user wishes to continue
        if user_confirmation in ["y", "yes"]:

            # Delete data
            helper.deleteData(cursor, conn, fetched_data)
            helper.success("successfully deleted from table")
            return

        # If the user wants to cancel
        elif user_confirmation in ["n", "no"]:
            helper.warning("cancelled")
            return
        
        helper.warning("invalid input")


def update(cursor, conn, key):
    """
    Updates a specified id's column
    
    """

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

        elif helper.validInputs(update_column, update_item):
            break

        helper.warning("invalid input")


    # Ask the user if they would like to continue
    while True:
        user_confirmation = input("proceed?(y/n): ").strip().lower()

        # If the user wishes to continue
        if user_confirmation in ["y", "yes"]:

            # Update data
            helper.updateData(cursor, conn, update_column, update_item, fetched_data[0][0], key)
            helper.success("successfully updated table")
            return

        # If the user wants to cancel
        elif user_confirmation in ["n", "no"]:
            helper.warning("cancelled")
            return
        
        helper.warning("invalid input")


def copy(cursor, key):
    """
    Copy an item of an id's specified column
    
    """

    while True:
        user_input = input("copy by id: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(user_input):
            return

        # Check if the user input is valid for parsing
        elif user_input and user_input.isdigit():
            break
            
        helper.warning("invalid input")

    # Query the database with its id
    fetched_data = cursor.execute("SELECT id, url, website, username, email, password FROM savings WHERE id=?", (user_input,)).fetchall()

    if fetched_data == None or len(fetched_data) < 1:
        helper.warning("no matching data")
        return

    # Prints search results
    helper.printTable(fetched_data, key)

    # Get user input for which column to copy
    while True:
        copy_column = input("column: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(copy_column):
            return

        elif copy_column.lower() in ["url", "website", "username", "email", "password"]:
            column_map = {
                "url": 1,
                "website": 2,
                "username": 3,
                "email": 4,
                "password": 5
            }
            
            fernet = Fernet(key)

            index = column_map[copy_column.lower()]
            token = fernet.decrypt(fetched_data[0][index].encode()).decode()
            pyperclip.copy(token)   # Copy the decrypted data
            helper.warning(f"{copy_column.lower()} copied to clipboard")
            return

        helper.warning("invalid column")


def settings(cursor, conn, key):
    """
    User config page
    
    """

    # Table option
    table = PrettyTable()
    table.add_row(["1. view data        2. Change email"])
    table.add_row(["3. Change username  4. Change password"])
    table.header = False
    table.align = "l"
    print(table)

    while True:
        option_input = input("option: ").strip()

        # See if the user wants to cancels
        if helper.wantsToExitInpuField(option_input):
            return

        elif option_input in ["1", "2", "3", "4"]:
            break

        helper.warning("invalid input")

    # Get users hashed password
    fetched_data = cursor.execute("SELECT * FROM user").fetchall()
    master_password_hash = fetched_data[0][3]
    while True:
        master_password_input = getpass.getpass("master password: ").strip()

        if helper.wantsToExitInpuField(option_input):
            return

        if hashlib.sha256(master_password_input.encode()).hexdigest() == master_password_hash:
            break

    if option_input == "1":
        helper.printTable(fetched_data, key, "user")

    # Email
    elif option_input == "2":
        while True:
            new_email_input = input("change email to: ").strip()
            
            if helper.wantsToExitInpuField(new_email_input):
                return
            
            elif helper.validInputs("email", new_email_input):
                break

    # Username
    elif option_input == "3":
        while True:
            new_username_input = input("change username to: ").strip()

            if helper.wantsToExitInpuField(new_username_input):
                return

            elif helper.validInputs("username", new_username_input):
                break

    # Password
    elif option_input == "4":
        while True:
            new_password_input = input("change password to: ").strip()

            if helper.wantsToExitInpuField(new_password_input):
                return

            elif helper.validInputs("password", new_password_input):
                break

    if option_input in ["2", "3", "4"]:
        # Ask the user if they would like to continue
        while True:
            user_confirmation = input("proceed?(y/n): ").strip().lower()

            # If the user wishes to continue
            if user_confirmation in ["y", "yes"]:

                # Update data
                if option_input == "2":

                    # Get users hashed password
                    data = cursor.execute("SELECT * FROM user").fetchall()[0]
                    master_password_hash = data[3]

                    while True:
                        master_password_input = getpass.getpass("master password: ").strip()

                        if helper.wantsToExitInpuField(master_password_input):
                            return

                        elif hashlib.sha256(master_password_input.encode()).hexdigest() == master_password_hash:
                            helper.changeEmail(cursor, conn, master_password_input, new_email_input, key)
                            break

                elif option_input == "3":
                    helper.updateData(cursor, conn, "username", new_username_input, 1, key, "user")

                elif option_input == "4":
                    helper.changePassword(cursor, conn, new_password_input, key)

                helper.success("requires login")
                exit()

            # If the user wants to cancel
            elif user_confirmation in ["n", "no"]:
                helper.warning("cancelled")
                return

            helper.warning("invalid input")


def help():
    """
    A list of all of the valid commands and what they do

    """

    table = PrettyTable()
    table.add_row(["[GENERAL COMMANDS]"])
    table.add_row(["'help'              help page"])
    table.add_row(["'/display'          displays saved data"])
    table.add_row(["'//display'         displays saved data (descending)"])
    table.add_row(["'/new '             saves new data"])
    table.add_row(["'/search'           searches data"])
    table.add_row(["'/delete'           deletes data"])
    table.add_row(["'/update'           updates data"])
    table.add_row(["'/settings'         configure user data"])
    table.add_row(["'clear'             clears the screen"])
    table.add_row(["'exit'/'quit'       kills the program"])
    table.add_row([""])
    table.add_row(["[INPUT COMMANDS]"])
    table.add_row(["'//c'               exists out of input fields"])
    table.add_row(["'random'            generates a random password of 20 chars"])
    table.add_row(["'random LENGTH'     specifies the length of the password"])
    table.add_row(["'email'             inputs user email from the 'register' page"])

    # Table formatting
    table.align = "l"
    table.header = False
    print(table)