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
import hashlib

BLOCK_COUNT = 4
ROUNDS = 4

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
                    ciphertext = encrypt(text,key) # Encrypt string `decrypted` with key `key`
                    file = open(f"{fileName}.out", "w") # Open file in write mode
                    file.write(ciphertext) # Write encrypted string to file contents
                    file.close() # Close file
                    print(f"--- OUTPUT to '{fileName}.out' ---")
                    print("--- FINISH ENCRYPTION ---")
                else:
                    return errorMessage("Key not specified!")
            elif mode == "decrypt" or mode == "d":
                print("--- START DECRYPTION ---")
                key = solve(text) # Find correct key
                print("--- KEY SOLVED ---")
                plaintext = decrypt(text, key)
                file = open(f"{fileName}.out", "w") # Open file in write mode
                file.write(plaintext) # Write decrypted string to file contents
                file.close() # Close file
                print("--- FINISH DECRYPTION ---")
        else:
            return errorMessage("File not specified!")
    else:
        return errorMessage("Invalid mode specified!")

def encrypt(plaintext, key): # Encrypt string with given key  
    ciphertext = ""
    n = BLOCK_COUNT # Amount of blocks to split into
    blockSize = (int)(n * math.ceil(len(plaintext)/n) / n) # Size of blocks
    blocks = [plaintext[i:i+blockSize] for i in range(0,len(plaintext), blockSize)] # Split string into `n` even parts

    if len(blocks[-1]) < blockSize: # If last block not full
        for i in range(len(blocks[-1]),blockSize): # Fill remaining space with whitespace
            blocks[-1] += " "

    for block in blocks:
        # print(block)
        L = [""] * (ROUNDS + 1) # Set L/R, where 0 is initial,
        R = [""] * (ROUNDS + 1) # and n+1 is ciphertext
        K = [""] * (ROUNDS + 1) # Set subKeys
        
        # Split blocks into even L/R sides
        pieceSize = (int)(blockSize/2)
        L[0] = block[0:pieceSize]
        R[0] = block[pieceSize:blockSize]
        K[0] = genSubKey(key)

        # print(f"L0 {L[0]}")
        # print(f"R0 {R[0]}")
        # print(f"K0 {K[0]}")

        for i in range(1,ROUNDS+1): # Iterate through rounds, including final ciphertext round
            # print(f"Round {i}")
            # print(f"XOR L/R for round {xor(L[i],R[i])}")
            L[i] = R[i-1] # Assign L to past R (Swap)
            R[i] = xor(L[i-1], roundFunc(R[i-1],K[i-1],i)) # Complete XOR on past L and past F(R,K)
            K[i] = genSubKey(L[i], K[0]) # Generate subkey for round using CBC (Cipher Block Chaining), combining initial key with previous value

            # print(f"L{i+1} {L[i]}")
            # print(f"R{i+1} {R[i]}")
            # print(f"K{i+1} {K[i]}")
        ciphertext += (L[ROUNDS] + R[ROUNDS]) # Re-combine final L/R for block and add to block
    return ciphertext

def decrypt(ciphertext, key): # Decrypt string with given key
    plaintext = ""
    return plaintext

def solve(ciphertext): # Get key of encrypted string
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

def genSubKey(a,b=""): # Generate round Sub-Key (SHA256), TODO: Add secret?
    return hashlib.sha256((a + b).encode()).hexdigest()

def xor(s1,s2): # Perform XOR on two strings
    # Creates tuples of nth letter of both strings.
    # Then performs XOR on each ASCII value of the
    # characters, and returns the value as a character.
    return "".join([chr(ord(a)^ord(b)) for a,b in zip(s1,s2)])

def roundFunc(s,k,i): # TODO: Add pow(s*k,i)?
    # Complete round function on R and Key.
    # Used similar round function from research. github/filgut1
    k = bintoint(strtobin(k)) # Convert K from String to Binary represented as Int
    s = bintoint(strtobin(s)) # Convert S from String to Binary represented as Int
    r = pow(s*k,i) # Complete work on S and K
    return bintostr(inttobin(r)) # Convert R from Int representation of Bin to Str

def strtobin(s): # Convert String to Binary
    return "".join(format(ord(i), "08b") for i in s)

def bintostr(b): # Convert Binary to String
    return "".join(chr(int(b[i: i+8],2)) for i in range(0, len(b), 8)) # Convert every byte of binary to character, and join as string

def bintoint(b): # Convery Binary to Int (Base2)
    return int(b,2)

def inttobin(i): # Convert Int to Binary
    return bin(i)

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
            plaintext = input("Enter message: ")
            key = input("Enter key: ")
            if key != "":
                print("--- START ENCRYPTION ---")
                print(f"Encrypted: {encrypt(plaintext,key)}") # Output encrypted value
                print("--- FINISH ENCRYPTION ---")
            else:
                return errorMessage("Key not specified!")
        elif option == 2: # Decrypt
            ciphertext = input("Enter message: ")
            print("--- START DECRYPTION ---")
            key = solve(ciphertext) # Find correct key
            print("--- KEY SOLVED ---")
            print(f"Key: {key}") # Decrypt string recursively, finding correct key
            print(f"Decrypted: {decrypt(ciphertext,key)}") # Decrypt string recursively, finding correct key
            print("--- FINISH DECRYPTION ---")
        elif option == 3: # Exit
            print("--- GOODBYE ---")
            menuLoop = False
        else:
            return errorMessage("Invalid option!")

if __name__ == '__main__': main()