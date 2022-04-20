# Feistel Cipher Decryption/Encryption
My implementation of the *Feistel Cipher* in Python. I have documented a few challenges I found when developing the cipher, to document my reasoning for some choices. 

Ideally, I would be able to produce a more secure cipher, given a better understanding of these issues.

## Usage
```
python3 feistel.py 
    -m (e|encrypt, d|decrypt, i|interactive) 
    [-f <file> (required if -m not i|interactive)]
    [-k <key> (required if -m not i|interactive)]
```

## Demo
Using the plaintext:
```
At seventeen minutes past four in the afternoon, whilst the passengers were assembled at lunch in the great saloon, a slight shock was felt on the hull of the Scotia.
```
With key `KEY` gives the ciphertext:
```
uc_]"NEpr#BE
wCd"gM^a@0sO`p8 Y$F:P1ct`sL,Z0gg_K$w40bQ"Rrr89yoF7!f r ig	H#ab7f_-9:oHuXz\qe
d54Ru+]9 *R^w<re2f0i\h;!Q2 X^{7;1)^8q5jo_<]wsa2<J6{x)3#
```
Decrypting with the provided key gives the same plaintext result.

## Challenges
### Key Generation
I used a Cipher Block Chaining (CBC) method to generate the keys for each round, which utilises text from the current round (Specifically, the unaltered side) to create a unique key that will only relate to that round (And cannot be generated with the same key/rounds, but different input text). This provides more security than traditional methods such as Electronic Code Book (ECB), which doesn't utilise text rounds to generate keys, only the round iterator and the current key.

I was able to get this correct:
```
Encryption
K0 '3363a903197e3744cb71d856b9a02ebc203d0a67ced74ab2f95c779e2f282b73'
K1 'bf978b95e370426459e2d8fdcdff335ff24aa81896e0747b44cef5da24dc1fec'
K2 'bba2b16aa656c15ef85467c2824522a5cd456580e662185e9ab2249db6bfd2c2'
K3 '42e5f09c0c59f527fc15558f1dcde35fdce50c153ff55841fd43c52d57762585'
K4 '2b872e20feafa1282c680c7009a357ae3e741062a72505624c5a16cd3ca55127'
```
```
Decryption
K0 '2b872e20feafa1282c680c7009a357ae3e741062a72505624c5a16cd3ca55127'
K1 '42e5f09c0c59f527fc15558f1dcde35fdce50c153ff55841fd43c52d57762585'
K2 'bba2b16aa656c15ef85467c2824522a5cd456580e662185e9ab2249db6bfd2c2'
K3 'bf978b95e370426459e2d8fdcdff335ff24aa81896e0747b44cef5da24dc1fec'
K4 '3363a903197e3744cb71d856b9a02ebc203d0a67ced74ab2f95c779e2f282b73'
```
As you can see, the key generation both ways is correct, meaning that the text is correct. However, as described in the next section, I was unable to use this to then produce a more secure round function.

### Round Function
I was only able to implement a two-way round function with operations such as simply passing the same input text, or passing the XOR of the two strings. 

When using a more advanced round function, and running the encrypted text through the same function to decrypt, the text is unreadable. I am only able to get a readable decrypted value when using a round function that is two-way (Cannot use pow/etc), unless it is allowed to use separate round functions.

To implement more secure *Round Functions*, I believe I would have to have separate encryption/decryption functions, that reverse the operations. I'm unsure on this, as I was unable to find as much research on *Round Functions*.

In addition, a more secure cipher would use different *Round Functions* per round.

### Decryption/Encryption Functions
Due to the two above problems, I attempted to separate the decryption/encryption functions and produce the same keys in reverse, for the round function.

Running the encrypted ciphertext through the encryption algorithm again will produce the original plaintext (Given the correct key). However, it will produce different keys (given the same text/key combination as before):
```
Encryption
K0 '3363a903197e3744cb71d856b9a02ebc203d0a67ced74ab2f95c779e2f282b73'
K1 'bf978b95e370426459e2d8fdcdff335ff24aa81896e0747b44cef5da24dc1fec'
K2 'bba2b16aa656c15ef85467c2824522a5cd456580e662185e9ab2249db6bfd2c2'
K3 '42e5f09c0c59f527fc15558f1dcde35fdce50c153ff55841fd43c52d57762585'
K4 '2b872e20feafa1282c680c7009a357ae3e741062a72505624c5a16cd3ca55127'
```
```
Decryption
K0 '29560573abcf5cf9cb612b38c291f1397aef8105ce895595874f5d1f390280b6'
K1 '2b872e20feafa1282c680c7009a357ae3e741062a72505624c5a16cd3ca55127'
K2 '42e5f09c0c59f527fc15558f1dcde35fdce50c153ff55841fd43c52d57762585'
K3 'bba2b16aa656c15ef85467c2824522a5cd456580e662185e9ab2249db6bfd2c2'
K4 'bf978b95e370426459e2d8fdcdff335ff24aa81896e0747b44cef5da24dc1fec'
```
This would have provided problems if I used more complex *Round Functions*.