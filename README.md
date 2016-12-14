# Practical-Crypto
This will contain the class projects I take up during the Practical Cryptographic Systems taught by Dr Matt Green at Johns Hopkins University


1. aes_cbc_enc_hmac_sha1.py: In this project we were required to implement a python based encrytion/decryption system. If you look at the code, there are some obvious security holes (using SHA1, mac then encrypt with padding not included in MAC). These were a part of the guidelines of implementation that was expected from us. The aim of this exercise was to give us first hand experience of how to implement an encryption/decryption scheme, what goes on inside HMAC and what and where the loopholes in the mechanism are. 

2. JMessenger : This project was about writing a messaging client that would communicate with peers on client server based system. The clients would generate RSA and DSA public-private key pair and share the public keys with the JMessage - Server for encryption and signing respectively. The server communicates with the various clients over *HTTP* and provides them with public keys of the peer they want to converse with. The *initiator* then generates a symmetric key, encrypts the message with this key, then encrypts the key with the receiver's public encryption key and sends both the key and the message along with a signature on this data, to the peer (this has some similarity to what imessage *used* to do). if you look at the implementation closely, you would notice that there are some obvious vulnerabilities/weak points (pkcs1v1.5/SHA1 signatures). Don't fret, the JMessenger Client is weak by design purposefully. The aim of the exercise like the previous one was to get a first hand experience of what a cryptographically vulnerable/weak system would look like. The next exercise if obviously to try to harden your own and break your peers' implementation. 

3. Breaking JMessenger : This project was the last leg of a two phase assignment wherein we were required to break a given implementation of the JMessenger Messaging System (Refer point 2). The provided implementation had a missing CRC check which allows an attacker to maul the messages. The attack goes like this:

>> Alice and Bob are communicating with each other. After every message that Alice sends to Bob, as soon as Bob reads it, it will send out a read receipt to Alice. 

>> Intercept the message going from Alice to Bob. Remove Alice's signature from the message. Maul the sender ID in the message to atacker's sender id. Send the message, if a read receipt is received it implies the message was accepted. 

>> Jmessanger uses PKCS% paddding. Given that, once the sender id has been mauled, resend the same message only this time maul the last byte of the padding till it gets accepted. Once the mauled padding is accepted attacker will get a read receipt after which attacker can extract what the original padding would have been. 

>> After the padding is known keep progressing forward, mauling the message to have increasing padding once byte after the other, every time a read receipt is received, it implies that the padding was successful and the attacker can extract the byte. 


The attack is not as straight forward as it requires some trickery to go around the CRC bytes and to extract messages that are longer than 16 bytes (max padding). Will be uploading the code once the assignment deadline passes. 
