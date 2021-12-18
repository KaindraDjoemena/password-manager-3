# Dependencies
import os
import helper
import sqlite3
from pages import register
from pages import login
from pages import displayCards
from pages import newCard
from pages import search
from pages import delete
from pages import update 
from pages import help


# Connect with the databse
conn = sqlite3.connect("user.db")
cursor = conn.cursor()


# Main function
def main(key):
    while True:
        while True:
            user_input = input(">>").strip().lower()
            if helper.isValid(user_input):
                break
            helper.warning("invalid input")

        # Page commands
        if user_input[0] == "/":
            
            # Displays user data
            if user_input == "/display":
                displayCards(key)

            # Makes new cards
            elif user_input == "/new":
                newCard(key)
            
            # Search data
            elif user_input == "/search":
                search(key)
            
            # Delete data/card
            elif user_input == "/delete":
                delete(key)
            
            # Update data/card
            elif user_input == "/update":
                update(key)
            
            else:
                helper.warning("no such command")

        # Clears terminal
        elif user_input == "clear":
            os.system("cls")

        # Quitting the program
        elif user_input in ["quit", "exit"]:
            conn.commit()
            conn.close()
            exit()
        
        elif user_input == "help":
            help()

        else:
            helper.warning("no such command")


if __name__ == "__main__":
    # Try accessing these tables and see if they exist or not
    try:
        cursor.execute("SELECT * FROM user")
        cursor.execute("SELECT * FROM savings")
        conn.commit()
    except:
        register()

    key = login()
    main(key)