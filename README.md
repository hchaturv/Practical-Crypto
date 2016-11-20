# Practical-Crypto
This will contain the class projects I take up during the Practical Cryptographic Systems taught by Dr Matt Green at Johns Hopkins University


1. aes_cbc_enc_hmac_sha1.py: In this project we were required to implement a python based encrytion/decryption system. If you look at the code, there are some obvious security holes (using SHA1, mac then encrypt with padding not included in MAC). These were a part of the guidelines of implementation that was expected from us. The aim of this exercise was to give us first hand experience of how to implement an encryption/decryption scheme, what goes on inside HMAC and what and where the loopholes in the mechanism are. 

2. JMessenger : This project was about writing a messaging client that would communicate with peers on a "Kerberos-like" system. The clients would generate RSA and DSA public-private key pair and share the public keys with the JMessage - Server for encryption and signing respectively. The server communicates with the various clients over *HTTP* and provides them with public keys of the peer they want to converse with. The *initiator* then generates a symmetric key, encrypts the message with this key, then encrypts the key with the receiver's public encryption key and sends both the key and the message along with a signature on this data, to the peer (this has some similarity to what imessage *used* to do). if you look at the implementation closely, you would notice that there are some obvious vulnerabilities/weak points (pkcs1v1.5/SHA1 signatures). Don't fret, the JMessenger Client is weak by design purposefully. The aim of the exercise like the previous one was to get a first hand experience of what a cryptographically vulnerable/weak system would look like. The next exercise if obviously to try to harden your own and break your peers' implementation. 
