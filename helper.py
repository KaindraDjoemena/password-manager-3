# Helper functions for the main file "main.py"
import re
import random
import validators
from random import choices
from prettytable import PrettyTable
from prettytable import NONE
from prettytable import HEADER
from cryptography.fernet import Fernet


# Check if the input is valid
def isValid(user_input):
    if " " not in user_input and user_input:
        return True
    return False


# Warning formatting
def warning(message):
    print(f"  <{message}>")


# Success formatting
def success(message):
    print(f"[{message}]")


# Check if email is valid
def emailIsValid(email_input):
    regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    if re.fullmatch(regex, email_input):
        return True
    return False


# See if the user wants to get out of filling an input field
def wantsToExitInpuField(user_input):
    if user_input == "//c":
        warning("action cancelled")
        return True
    return False


# Check if the password is valid
def passwordIsValid(password_input):
    if len(password_input) > 8 and " " not in password_input:
        return True
    return False


# Generate a random password
def generatePassword(len=20):
    chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+[]|;:,<.>/?"
    
    password = ""
    for _ in range(len):
        password += random.choice(chars)
    return password


def printTable(fetched_data, key):
    """
    Prints the data/rows in a table format
    
    """

    table = PrettyTable()
    table.field_names = ["ID", "URL", "Website", "Username", "Email", "Password"]
    fernet = Fernet(key)
    for data in fetched_data:
        table.add_row([
            data[0],
            fernet.decrypt(data[1].encode()).decode(),
            fernet.decrypt(data[2].encode()).decode(),
            fernet.decrypt(data[3].encode()).decode(),
            fernet.decrypt(data[4].encode()).decode(),
            fernet.decrypt(data[5].encode()).decode()
        ])

    # Formatting the table
    table.left_padding_width = 1
    table.vrules = NONE
    table.hrules = HEADER
    print(table)
    print()


def searchTable(cursor, key, item):
    """
    Searches for a row of data by specifying its website name
    It fetches all encrypted data first, then compares each row's website decrypted column to see if it matches
    
    """


    fernet = Fernet(key)

    # Query the database
    fetched_data = cursor.execute("SELECT id, url, website, username, email, password FROM savings").fetchall()

    # Check if we get any data in return
    if len(fetched_data) < 1:
        return None

    # See if the user input is close to any saved website name
    search_result = []
    for data in fetched_data:
        token = fernet.decrypt(data[2].encode()).decode()
        if item.lower() in token.lower():
            search_result.append(data)
    
    return search_result


def updateData(cursor, conn, update_column, update_item, id, key):
    """
    For some reason, sqlite3 can't have placeholders for their column name, so I have to hard code it
    
    """

    fernet = Fernet(key)

    # Update the id's column
    if update_column == "url":
        cursor.execute("UPDATE savings SET url=? WHERE id=?", (fernet.encrypt(update_item.encode()).decode(), id))

    elif update_column == "website":
        cursor.execute("UPDATE savings SET website=? WHERE id=?", (fernet.encrypt(update_item.encode()).decode(), id))

    elif update_column == "username":
        cursor.execute("UPDATE savings SET username=? WHERE id=?", (fernet.encrypt(update_item.encode()).decode(), id))

    elif update_column == "email":
        cursor.execute("UPDATE savings SET email=? WHERE id=?", (fernet.encrypt(update_item.encode()).decode(), id))

    elif update_column == "password":
        cursor.execute("UPDATE savings SET password=? WHERE id=?", (fernet.encrypt(update_item.encode()).decode(), id))
    conn.commit()


# Delete data by its id
def deleteData(cursor, conn, fetched_data):

    for data in fetched_data:
        id = data[0]
        cursor.execute("DELETE FROM savings WHERE id=?", (id,))

    conn.commit()


def validInputs(column, item):
    """
    See if the user input is valid
    
    """

    if column == "url":
        if validators.url(item):
            return True

    elif column == "website":
        if " " not in item and item:
            return True

    elif column == "username":
        return True

    elif column == "email":
        if emailIsValid(item):
            return True

    elif column == "password":
        if passwordIsValid(item):
            return True
    
    return False