# encrypted-messaging
Messaging app in Node, where messages are E2E encrypted with public keys from members part of the chat room.

**IMPORTANT TO NOTE!!!** Not meant to be used in production where safety is a concern. You and I just wanna learn encrypting communication, got it? Okay, good!

I did that code in copy-paste style from [this user](https://github.com/billautomata/) from this [repository](https://github.com/billautomata/encrypted-socket.io-chatroom) on GitHub. 

Couple of differences is that my project uses `crypto.createCipheriv` and `crypto.createDecipheriv` functions for more randomized encryption with initialization vectors, and on client-side, `randNum` function with given digit creates a random ID from numbers, Estonian, Latvian, Lithuanian letters and is used for client socket ID. Not sure why I did that, but I did that.

Crypto proxy uses AES256 encryption. And for extra encryption, this project's server runs on HTTPS with SSL/TLS certificate. For `localhost`, I made self-assigned SSL certificate.

#

ellartdev 2020
