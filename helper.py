# Helper functions for the main file "main.py"

import re
import random
from random import choices

# Check if the input is valid
def isValid(user_input):
    if not user_input or " " in user_input or not user_input.isalnum():
        return False
    return True

# Warning formatting
def warning(message):
    print(f"  <{message}>")

# Check if email is valid
def emailIsValid(email_input):
    regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    if re.fullmatch(regex, email_input):
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