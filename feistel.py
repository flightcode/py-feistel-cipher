#!/usr/bin/env python3

# Feistel cipher encoder/decoder.
# github.com/flightcode
# 2022
# USAGE: 
#   python3 feistel.py 
#       -m (e|encrypt, d|decrypt, i|interactive) 
#       [-f <filename> (required if -m not i|interactive)]
#       [-k <key> (required if -m e|encrypt)]

import sys # For CLI rguments
import getopt # Parses CLI arguments
import itertools # Code-efficient iterators
import string
import math

def main(): # Welcome message and run menu
    print("--- FEISTEL CIPHER ----")
    print("--- FLIGHTCODE 2022 ----")

    fileName = "" # File to parse
    mode = "" # Mode (interactive is for testing or if user wants a menu)
    key = "" # If applicable, if not provided for decode, will attempt to crack. Required for encode.

    try: # Attempt to parse arguments (Strip first argument (Command))
        opts, args = getopt.getopt(sys.argv[1:], "m:f:k:")
    except:
        errorMessage("Unable to parse arguments!")

    for opt, arg in opts: # Assign from arguments 
        if opt in ['-f']:
            fileName = arg
        elif opt in ['-m']:
            mode = arg
        elif opt in ['-k']:
            key = arg

    if mode == "interactive" or mode == "i":
        menu()
    elif mode == "encrypt" or mode == "e" or mode == "decrypt" or mode == "d":
        if fileName != "":
            file = open(fileName, "r") # Open file in read mode
            text = file.read() # Read file contents to string
            file.close() # Close file
            if mode == "encrypt" or mode == "e":
                if key != "":
                    print("--- START ENCRYPTION ---")
                    encrypted = encrypt(text,key) # Encrypt string `decrypted` with key `key`
                    file = open(f"{fileName}.out", "w") # Open file in write mode
                    file.write(encrypted) # Write encrypted string to file contents
                    file.close() # Close file
                    print(f"--- OUTPUT to '{fileName}.out' ---")
                    print("--- FINISH ENCRYPTION ---")
                else:
                    return errorMessage("Key not specified!")
            elif mode == "decrypt" or mode == "d":
                print("--- START DECRYPTION ---")
                key = solve(text) # Find correct key
                print("--- KEY SOLVED ---")
                decrypted = decrypt(text, key)
                file = open(f"{fileName}.out", "w") # Open file in write mode
                file.write(decrypted) # Write decrypted string to file contents
                file.close() # Close file
                print("--- FINISH DECRYPTION ---")
        else:
            return errorMessage("File not specified!")
    else:
        return errorMessage("Invalid mode specified!")

def encrypt(decrypted, key): # Encrypt string with given key    
    encrypted = ""
    n = 4 # Amount of blocks to split into, TODO: Update to add user-option
    size = (int)(n * math.ceil(len(decrypted)/n) / n) # Size of blocks
    blocks = [decrypted[i:i+size] for i in range(0,len(decrypted), size)] # Split string into `n` even parts

    if len(blocks[-1]) < size: # If last block not full
        for i in range(len(blocks[-1]),size): # Fill remaining space with whitespace
            blocks[-1] += " "

    for block in blocks:
        print(block)

    return encrypted

def decrypt(encrypted, key): # Decrypt string with given key
    decrypted = ""
    return decrypted

def solve(encrypted): # Get key of encrypted string
    key = ""
    return key

def freqTest(message): # Test frequency of string against English language alphabet frequencies using Chi-Squared Test (0 is most accurate)
    ENGLISH_FREQ = { # Frequencies of characters in English language
        "A": 0.08497, "B": 0.01492, "C": 0.02202, "D": 0.04253, "E": 0.11162, "F": 0.02228,
        "G": 0.02015, "H": 0.06094, "I": 0.07546, "J": 0.00153, "K": 0.01292, "L": 0.04025,
        "M": 0.02406, "N": 0.06749, "O": 0.07507, "P": 0.01929, "Q": 0.00095, "R": 0.07587,
        "S": 0.06327, "T": 0.09356, "U": 0.02758, "V": 0.00978, "W": 0.02560, "X": 0.00150,
        "Y": 0.01994, "Z": 0.00077,
    }
    testStatistic = 0.0
    for c in ENGLISH_FREQ: # Iterate through all characters
        if c in message:
            freq = message.count(c) / len(message) # Get occurrence of character in shift
            letterTestStatistic = ((freq - ENGLISH_FREQ[c]) ** 2) / ENGLISH_FREQ[c] #Get test statistic
            testStatistic += letterTestStatistic #Add test statistic to total
    return testStatistic

def errorMessage(message): # Print param 'message' formatted as ERROR
    print("--- ERROR ---")
    print(f"{message}")
    print("--- ERROR ---")

def menu(): # Menu Options
    menuLoop = True
    while menuLoop: # Run until user selects to exit
        print("")
        print("--- MENU ---")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        print("--- MENU ---")
        print("")
        option = int(input("Enter option: ")) # Get input as int
        print("")
        if option == 1: # Encrypt
            decrypted = input("Enter message: ")
            key = input("Enter key: ")
            if key != "":
                print("--- START ENCRYPTION ---")
                print(f"Encrypted: {encrypt(decrypted,key)}") # Output encrypted value
                print("--- FINISH ENCRYPTION ---")
            else:
                return errorMessage("Key not specified!")
        elif option == 2: # Decrypt
            encrypted = input("Enter message: ")
            print("--- START DECRYPTION ---")
            key = solve(encrypted) # Find correct key
            print("--- KEY SOLVED ---")
            print(f"Key: {solve(encrypted)}") # Decrypt string recursively, finding correct key
            decrypted = decrypt(encrypted, key)
            print(f"Decrypted: {decrypt(encrypted,key)}") # Decrypt string recursively, finding correct key
            print("--- FINISH DECRYPTION ---")
        elif option == 3: # Exit
            print("--- GOODBYE ---")
            menuLoop = False
        else:
            return errorMessage("Invalid option!")

if __name__ == '__main__': main()