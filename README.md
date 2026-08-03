# secure end to end encrypted chatting application
***note: must read the challenges that i face during the project developement, also snap and shots of working project is down in , github not being able to render those images so please click on them and those images will gonna open seperately in the new tab.***

index-
1. description
2. Features
3. challanges that i faced
4. snaps of working project
5. system architecture (pending)
6. workflow of code (status: pending , reason : too complex ... trying to make it less  complicative to write here but will gonna bring soon)




***Thankyou***

----


## description:
-  This is a python based , end to end encrypted terminal chat application over websockets

- this project demonstrates secure communication by utlizing RSA alogrithm for session key exchange ,and AES-GCM for fast authenticated message encryption . The Server acts purely as a router and public key directory

- server cannot read the contents of any messages

## Features:

- RSA key exchange algorithm
- AES-GCM message encrytion algorithm
- SHA-256 hashing algorithm for digital signature and padding during encryption
- websocket communication
- cryptography 
- Digital signature 
- Multi- client support
- AsyncIO
- 

## How it works(basic info):

1. client registers 
2. RSA public key established 
3. Messages encrypted using AES-GCM
4. Messages signed using RSA 
5. then send to the other user

## challenges that i faced:

*Yes i did vibe coding for developing this project but it is not all vibe coding i faced errors and bugs also some inefficiency in the code that i fixed myself and also by doing more vibecoding...*

- **session key race condition** (before it was just 1 variable for session key in client code ,but in this, it is a **two channel full duplex** system..... there was only one variable before in which both sides session keys gets stored but then gets replaced by the newer session key, to solve this problem i created two different variables for storing sender's session key and receiver's seession key so both keys get stores in different variable and do not replace each other)

- **inefficiency in sharing public RSA key** (in server code it was sharing public key everytime the message is being send , which is of no use ,because public key is already shared to the other user while eestablishing the session between them, so i changed it to share only when session key is being share)

*session gets established by exchanging session keys*

- **small bugs in coding** - had to write manually for avoiding the spaces which gets when you copys the code
  
- **upgrade related to print connected in the client code**- (here in this client code was being optimistic it was printing connected on the client side before server registeration of user's id gets done, if servverr reject's the user's id because of reasons like duplicacy then also connected gets printed on the client side .... so to tackle this inefficiency i made some changes in the server's and client's code so that server can send the status of registration to the client and then client can print that status to the user on the screen, that if registration was successfull or not is user'id is valid or not )


## SNAPS OF WORKING PROJECT:

<img width="1883" height="1034" alt="snap-1" src="https://github.com/user-attachments/assets/d09630e5-5902-4f93-ad83-88a97f36fc9c" />

*server and client initialization*

<img width="1853" height="1026" alt="snap-2" src="https://github.com/user-attachments/assets/4efc59e5-25ec-4cb1-b634-c77d16dc266b" />

*users entering username/user's id*

<img width="1919" height="1044" alt="snap-3" src="https://github.com/user-attachments/assets/30e3d2dd-8ac8-473a-8be3-302c7259b9ee" />

*exchanging messages, server cannot see anything in plain text and only sees gibberish data logs*

<img width="914" height="623" alt="snap-4" src="https://github.com/user-attachments/assets/c28bcf4b-a8e0-449e-8f92-85dbfb730416" />

*users got disconnected *

<img width="951" height="647" alt="snap5" src="https://github.com/user-attachments/assets/362af3c6-8863-4ad9-b780-16ffb1bddac7" />

*as you can see here that user is trying to send message to the user that is not logged in or in other words we can say that "didn't existed"*

<img width="1346" height="860" alt="snap-6" src="https://github.com/user-attachments/assets/66e833c8-4082-43ea-b36f-743b6484a3d7" />

*in this you can see i initialized a 3rd client.py and from there entering 1st user's id but because of duplicacy it gets rejected*
