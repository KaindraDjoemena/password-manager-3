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
from pages import copy


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
                displayCards(cursor, key)

            # Makes new cards
            elif user_input == "/new":
                newCard(cursor, conn, key)
            
            # Search data
            elif user_input == "/search":
                search(cursor, key)
            
            # Delete data/card
            elif user_input == "/delete":
                delete(cursor, conn, key)
            
            # Update data/card
            elif user_input == "/update":
                update(cursor, conn, key)
            
            # User can copy data
            elif user_input == "/copy":
                copy(cursor, key)

            else:
                helper.warning("no such command")

        # Clears terminal
        elif user_input == "clear":
            os.system("cls")
            helper.success("type 'help' for help")

        # Quitting the program
        elif user_input in ["quit", "exit"]:
            # conn.commit()
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
        register(cursor, conn)

    key = login(cursor)
    main(key)