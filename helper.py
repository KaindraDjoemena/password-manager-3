# Helper functions for the main file "main.py"
import re
import base64
import random
import hashlib
import validators
from random import choices
from prettytable import PrettyTable
from prettytable import NONE
from prettytable import HEADER
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


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


def generateKey(cursor, master_password_input):
    """
    Generate key with unhashed master_password + email
    
    """

    # Get users hashed password
    data = cursor.execute("SELECT * FROM user").fetchall()[0]
    email = data[2]
    salt = data[4]

    password = (master_password_input + email).encode("utf8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def printTable(fetched_data, key, table_name="savings"):
    """
    Prints the data/rows in a table format
    
    """

    fernet = Fernet(key)
    table = PrettyTable()
    if table_name == "savings":
        table.field_names = ["ID", "URL", "WEBSITE", "USERNAME", "EMAIL", "PASSWORD"]
        for data in fetched_data:
            table.add_row([
                data[0],
                fernet.decrypt(data[1].encode()).decode(),
                fernet.decrypt(data[2].encode()).decode(),
                fernet.decrypt(data[3].encode()).decode(),
                fernet.decrypt(data[4].encode()).decode(),
                fernet.decrypt(data[5].encode()).decode()
            ])
    
    elif table_name == "user":
        table.field_names = ["ID", "USERNAME", "EMAIL", "MASTER HASH"]
        for data in fetched_data:
            table.add_row([
                data[0],
                data[1],
                data[2],
                data[3]
            ])

    # Formatting the table
    table.left_padding_width = 1
    table.vrules = NONE
    table.hrules = HEADER
    print()
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


def updateData(cursor, conn, column, update_item, id, key, table="savings"):
    """
    For some reason, sqlite3 can't have placeholders for their column name, so I have to hard code it
    
    """

    fernet = Fernet(key)

    # Update the id's column
    if table == "savings":
        if column == "url":
            cursor.execute("UPDATE savings SET url=? WHERE id=?", (fernet.encrypt(update_item.encode()).decode(), id))

        elif column == "website":
            cursor.execute("UPDATE savings SET website=? WHERE id=?", (fernet.encrypt(update_item.encode()).decode(), id))

        elif column == "username":
            cursor.execute("UPDATE savings SET username=? WHERE id=?", (fernet.encrypt(update_item.encode()).decode(), id))

        elif column == "email":
            cursor.execute("UPDATE savings SET email=? WHERE id=?", (fernet.encrypt(update_item.encode()).decode(), id))

        elif column == "password":
            cursor.execute("UPDATE savings SET password=? WHERE id=?", (fernet.encrypt(update_item.encode()).decode(), id))
    
    elif table == "user":
        if column == "username":
            cursor.execute("UPDATE user SET username=? WHERE id=?", (update_item, id))

        elif column == "email":
            cursor.execute("UPDATE user SET email=? WHERE id=?", (update_item, id))

        elif column == "master_password":
            cursor.execute("UPDATE user SET master_password=? WHERE id=?", (update_item, id))
    
    conn.commit()


def changePassword(cursor, conn, new_password, key):
    """
    Get encrypt data, decrypt with the old key, encrypt all data with the new key
    
    """

    # Fetch encrypted data
    fetched_data = cursor.execute("SELECT * FROM savings").fetchall()
    if len(fetched_data) < 1:
        new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        updateData(cursor, conn, "master_password", new_password_hash, 1, key, "user")
        return

    fernet = Fernet(key)
    raw_data = []
    for data in fetched_data:
        decrypted_url = fernet.decrypt(data[1].encode()).decode()
        decrypted_website = fernet.decrypt(data[2].encode()).decode()
        decrypted_username = fernet.decrypt(data[3].encode()).decode()
        decrypted_email = fernet.decrypt(data[4].encode()).decode()
        decrypted_password = fernet.decrypt(data[5].encode()).decode()

        raw_data.append((
            data[0],
            decrypted_url,
            decrypted_website,
            decrypted_username,
            decrypted_email,
            decrypted_password
        ))

    # Update master password
    new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    updateData(cursor, conn, "master_password", new_password_hash, 1, key, "user")

    # Encrypt with new key
    id = 1
    new_key = generateKey(cursor, new_password)
    fernet = Fernet(new_key)
    for data in raw_data:

        updateData(cursor, conn, "url", data[1], id, new_key)
        updateData(cursor, conn, "website", data[2], id, new_key)
        updateData(cursor, conn, "username", data[3], id, new_key)
        updateData(cursor, conn, "email", data[4], id, new_key)
        updateData(cursor, conn, "password", data[5], id, new_key)

        id += 1


def changeEmail(cursor, conn, master_password_input, new_email, key):
    """
    Get encrypt data, decrypt with the old key, encrypt all data with the new key
    
    """

    # Fetch encrypted data
    fetched_data = cursor.execute("SELECT * FROM savings").fetchall()
    if len(fetched_data) < 1:
        updateData(cursor, conn, "email", new_email, 1, key, "user")
        return

    fernet = Fernet(key)
    raw_data = []
    for data in fetched_data:
        decrypted_url = fernet.decrypt(data[1].encode()).decode()
        decrypted_website = fernet.decrypt(data[2].encode()).decode()
        decrypted_username = fernet.decrypt(data[3].encode()).decode()
        decrypted_email = fernet.decrypt(data[4].encode()).decode()
        decrypted_password = fernet.decrypt(data[5].encode()).decode()

        raw_data.append((
            data[0],
            decrypted_url,
            decrypted_website,
            decrypted_username,
            decrypted_email,
            decrypted_password
        ))

    # Update email
    updateData(cursor, conn, "email", new_email, 1, key, "user")

    # Encrypt with new key
    id = 1
    new_key = generateKey(cursor, master_password_input)
    fernet = Fernet(new_key)
    for data in raw_data:

        updateData(cursor, conn, "url", data[1], id, new_key)
        updateData(cursor, conn, "website", data[2], id, new_key)
        updateData(cursor, conn, "username", data[3], id, new_key)
        updateData(cursor, conn, "email", data[4], id, new_key)
        updateData(cursor, conn, "password", data[5], id, new_key)

        id += 1


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