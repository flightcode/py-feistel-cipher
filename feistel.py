#!/usr/local/opt/python@3.10/bin/python3
# github.com/flightcode
# 2022

import time

def main():
    print("--- FEISTEL CIPHER ----")
    print("--- FLIGHTCODE 2022 ---")
    time.sleep(1)
    menu()

def decrypt(encrypted):
    print(f"Encrypted: {encrypted}")
    decrypted = encrypted
    print(f"Decrypted: {decrypted}")

def encrypt(decrypted):
    print(f"Decrypted: {decrypted}")
    encrypted = decrypted
    print(f"Encrypted: {encrypted}")

def errorMessage(message):
    print("--- ERROR ---")
    print(f"{message}")
    print("--- ERROR ---")

def menu():
    menuLoop = True
    while menuLoop:
        print("")
        print("--- MENU ---")
        print("1. Decrypt")
        print("2. Encrypt")
        print("3. Exit")
        print("--- MENU ---")
        print("")
        option = int(input("Enter option: "))
        print("")
        if option == 1:
            print("--- STARTING DECRYPT ---")
            decrypt("test")
            print("--- FINISHED DECRYPT ---")
        elif option == 2:
            print("--- STARTING ENCRYPT ---")
            encrypt("test")
            print("--- FINISHED ENCRYPT ---")
        elif option == 3:
            print("--- GOODBYE ---")
            menuLoop = False
        else:
            errorMessage("Invalid option!")

if __name__ == '__main__': main()