# secure end to end encrypted chatting application

## description:
-  This is a python based , end to end encrypted terminal chat application over websockets

- this project demonstrates secure communication by utlizing RSA alogrithm for fast, authenticated message encryption . The Server acts purely as a router and public key directory

- server cannot read the contents of any messages

## Features:

- RSA key exchange algorithm
- AES-GCM message encrytion algorithm
- SHA-256 hashing algorithm for digital signature and padding during encryption
- websocket communication
- cryptography 
- Digital signature 
- Multi- client support


## How it works(basic info):

1. client registers 
2. RSA public key established 
3. Messages encrypted using AES-GCM
4. Messages signed using RSA 

