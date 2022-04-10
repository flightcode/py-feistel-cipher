#!/usr/local/opt/python@3.10/bin/python3
# github.com/flightcode
# 2022

import time

def main(): # Welcome message and run menu
    print("--- FEISTEL CIPHER ----")
    print("--- FLIGHTCODE 2022 ----")
    time.sleep(1)
    menu()

def decrypt(encrypted): # Decrypt string
    print(f"Encrypted: {encrypted}")
    decrypted = encrypted
    print(f"Decrypted: {decrypted}")

def encrypt(decrypted): # Encrypt string
    print(f"Decrypted: {decrypted}")
    encrypted = decrypted
    print(f"Encrypted: {encrypted}")

def errorMessage(message): # Print param 'message' formatted as ERROR
    print("--- ERROR ---")
    print(f"{message}")
    print("--- ERROR ---")

def menu(): # Menu Options
    menuLoop = True
    while menuLoop: # Run until user selects to exit
        print("")
        print("--- MENU ---")
        print("1. Decrypt")
        print("2. Encrypt")
        print("3. Exit")
        print("--- MENU ---")
        print("")
        option = int(input("Enter option: ")) # Get input as int
        print("")
        if option == 1: # Decrypt
            print("--- STARTING DECRYPT ---")
            decrypt("test")
            print("--- FINISHED DECRYPT ---")
        elif option == 2: # Encrypt
            print("--- STARTING ENCRYPT ---")
            encrypt("test")
            print("--- FINISHED ENCRYPT ---")
        elif option == 3: # Exit
            print("--- GOODBYE ---")
            menuLoop = False
        else:
            errorMessage("Invalid option!")

if __name__ == '__main__': main()