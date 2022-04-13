#!/usr/bin/env python3

# Feistel cipher encoder/decoder.
# github.com/flightcode
# 2022
# USAGE: 
#   python3 feistel.py 
#       -m (e|encrypt, d|decrypt, i|interactive) 
#       [-f <file> (required if -m not i|interactive)]
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

    mode = "" # Interactive for testing or if user wants a menu
    fileName = "" # File to parse
    key = "" # Required for encode.

    try: # Attempt to parse arguments (Strip first argument (Command))
        opts, args = getopt.getopt(sys.argv[1:], "hm:f:k:", ["help","mode=","file=","key="])
    except:
        errorMessage("Unable to parse arguments!")
        print('Usage: ./feistel.py -m <mode> -f <file> -k <key>')
        print('Modes: e|encrypt')
        print('       d|decrypt')
        print('       i|interactive')
        exit()

    for opt, arg in opts: # Assign from arguments 
        if opt in ["-h","--help"]:
            print('Usage: ./feistel.py -m <mode> -f <file> -k <key>')
            print('Modes: e|encrypt')
            print('       d|decrypt')
            print('       i|interactive')
            exit()
        elif opt in ["-f","--file"]:
            fileName = arg
        elif opt in ["-m","--mode"]:
            mode = arg
        elif opt in ["-k","--key"]:
            key = arg

    if mode == "interactive" or mode == "i":
        menu()
    elif mode == "encrypt" or mode == "e" or mode == "decrypt" or mode == "d":
        if fileName != "":
            with open(fileName, "r") as file: # Open file in read mode
                text = file.read() # Read file contents to string
            if mode == "encrypt" or mode == "e":
                if key != "":
                    print("--- START ENCRYPTION ---")
                    ciphertext = encrypt(text,key) # Encrypt string `decrypted` with key `key`
                    with open(f"{fileName}.out", "w") as file: # Open file in write mode
                        file.write(ciphertext) # Write encrypted string to file contents
                    print(f"--- OUTPUT to '{fileName}.out' ---")
                    print("--- FINISH ENCRYPTION ---")
                else:
                    return errorMessage("Key not specified!")
            elif mode == "decrypt" or mode == "d":
                if key != "":
                    print("--- START DECRYPTION ---")
                    plaintext = decrypt(text, key)
                    with open(f"{fileName}.out", "w") as file: # Open file in write mode
                        file.write(plaintext) # Write decrypted string to file contents
                    print(f"--- OUTPUT to '{fileName}.out' ---")
                    print("--- FINISH DECRYPTION ---")
                else:
                    return errorMessage("Key not specified!")
        else:
            return errorMessage("File not specified!")
    else:
        return errorMessage("Invalid mode specified!")

def encrypt(plaintext, key): # Encrypt string with given key through feistel structure  
    ciphertext = ""
    blockSize = calcBlockSize(plaintext, BLOCK_COUNT) # Size of blocks
    blocks = createBlocks(plaintext, blockSize)
    for block in blocks:
        # print(f"'{block}'") # DEBUGGING
        K, L, R = createBlockRounds(ROUNDS)
        pieceSize = (int)(blockSize/2)

        R[0] = block[pieceSize:blockSize] # Split blocks into even L/R sides
        L[0] = block[0:pieceSize]
        K[0] = genSubKey(L[0],key)
        print(f"K{0} '{K[0]}'") # DEBUGGING
        # print(f"L0 '{L[0]}'") # DEBUGGING
        # print(f"R0 '{R[0]}'") # DEBUGGING

        for i in range(1,ROUNDS+1): # Iterate through rounds, including final ciphertext round
            # print(i) # DEBUGGING
            L[i] = R[i-1] # Assign L to past R (Swap)
            K[i] = genSubKey(L[i], key) # Generate subkey for round using CBC (Cipher Block Chaining), combining initial key with previous value
            R[i] = xor(L[i-1], roundFunc(R[i-1],K[i],i)) # Complete XOR on past L and past F(R,K)
            print(f"K{i} '{K[i]}'") # DEBUGGING
        # print(f"L{ROUNDS} '{L[ROUNDS]}'") # DEBUGGING
        # print(f"R{ROUNDS} '{R[ROUNDS]}'") # DEBUGGING
        ciphertext += (R[ROUNDS] + L[ROUNDS]) # Re-combine final L/R (swapped again) for block and add to block
    return ciphertext

def decrypt(ciphertext, key): # Decrypt string with given key through feistel structure  
    plaintext = ""
    blockSize = calcBlockSize(ciphertext, BLOCK_COUNT) # Size of blocks
    blocks = createBlocks(ciphertext, blockSize)
    for block in blocks:
        # print(f"'{block}'") # DEBUGGING
        K, L, R = createBlockRounds(ROUNDS)
        pieceSize = (int)(blockSize/2)

        R[0] = block[pieceSize:blockSize] # Split blocks into even L/R sides (Swap L/R from encryption output)
        L[0] = block[0:pieceSize]
        K[0] = genSubKey(R[0],key)
        print(f"K{0} '{K[0]}'") # DEBUGGING
        # print(f"L{ROUNDS} '{L[ROUNDS]}'") # DEBUGGING
        # print(f"R{ROUNDS} '{R[ROUNDS]}'") # DEBUGGING

        for i in range(1,ROUNDS+1): # Iterate through rounds, including final ciphertext round
            # print(i) # DEBUGGING
            L[i] = R[i-1] # Assign L to past R (Swap)
            R[i] = xor(L[i-1], roundFunc(R[i-1],K[i-1],i)) # Complete XOR on past L and past F(R,K)
            K[i] = genSubKey(R[i], key) # Generate subkey for round using CBC (Cipher Block Chaining), combining initial key with previous value
            print(f"K{i} '{K[i]}'") # DEBUGGING
        # print(f"L0 '{L[0]}'") # DEBUGGING
        # print(f"R0 '{R[0]}'") # DEBUGGING
        plaintext += (R[ROUNDS] + L[ROUNDS]) # Re-combine final L/R for block and add to block
    return plaintext

def calcBlockSize(s,count): # Calculate block size given string and desired amount of blocks
    return (int)(count * math.ceil(len(s)/count) / count)

def createBlocks(s,blockSize): # Create balanced blocks given string and desired block size
    blocks = [s[i:i+blockSize] for i in range(0,len(s), blockSize)] # Split string into `n` even parts
    if len(blocks[-1]) < blockSize: # If last block not full
        for i in range(len(blocks[-1]),blockSize): # Fill remaining space with whitespace
            blocks[-1] += " "
    return blocks

def createBlockRounds(r): # Create initial K/L/R arrays based on desired amount of rounds
    K = [""] * (r + 1) # Set subKeys
    L = [""] * (r + 1) # Set L/R, where 0 is initial,
    R = [""] * (r + 1) # and n+1 is ciphertext
    return K,L,R

def genSubKey(a,b=""): # Generate round Sub-Key (SHA256), TODO: Add secret?
    return hashlib.sha256((a + b).encode()).hexdigest()

def xor(s1,s2): # Perform XOR on two strings
    # Creates tuples of nth letter of both strings.
    # Then performs XOR on each ASCII value of the
    # characters, and returns the value as a character.
    return "".join(chr(ord(a)^ord(b)) for a,b in zip(s1,s2))

def roundFunc(s,key,i): # Performs 'scramble' function on R side of block and Key.
    # Complete round function on R and Key.
    # Used similar round function from research. github/filgut1
    # When using this round function, and running the encrypted text through the same 
    # function to decrypt, the text is unreadable. I am only able to get a readable
    # decrypted value when using a round function that is two-way (Cannot use pow/etc),
    # unless it is allowed to use separate round functions.
    key = bintoint(strtobin(key)) # Convert K from String to Binary represented as Int
    s = bintoint(strtobin(s)) # Convert S from String to Binary represented as Int
    # r = pow((s*key),i) # Complete work on S and K
    r = s^key # DEBUGGING
    return bintostr(inttobin(r)) # Convert R from Int representation of Bin to Str

def strtobin(s): # Convert String to Binary
    return "".join("{:08b}".format(ord(c)) for c in s)

def bintostr(b): # Convert Binary to String
    return "".join(chr(int(b[i: i+7],2)) for i in range(0, len(b), 8)) # Convert every byte of binary to character, and join as string

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
            key = input("Enter key: ")
            if key != "":
                print("--- START DECRYPTION ---")
                print(f"Decrypted: {decrypt(plaintext,key)}") # Output decrypted value
                print("--- FINISH ENCRYPTION ---")
            else:
                return errorMessage("Key not specified!")
        elif option == 3: # Exit
            print("--- GOODBYE ---")
            menuLoop = False
        else:
            return errorMessage("Invalid option!")

if __name__ == '__main__': main()