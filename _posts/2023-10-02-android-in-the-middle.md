---
title: Hack The Box - Android-in-the-Middle
date: 2023-02-10 00:28:00 -500
categories: [ctf,hack the box]
tags: [writeup,walkthrough,crypto]
---

I'm back at it again with another little challenge from HackTheBox. This time it's a crypto one, called *Android-in-the-Middle*. 

To know what we have to do and how to get the flag, let's look at the code they give us in `source.py` :

```python
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import hashlib
import random
import socketserver
import signal

FLAG = "HTB{--REDACTED--}"
DEBUG_MSG = "DEBUG MSG - "
p = 0x509efab16c5e2772fa00fc180766b6e62c09bdbd65637793c70b6094f6a7bb8189172685d2bddf87564fe2a6bc596ce28867fd7bbc300fd241b8e3348df6a0b076a0b438824517e0a87c38946fa69511f4201505fca11bc08f257e7a4bb009b4f16b34b3c15ec63c55a9dac306f4daa6f4e8b31ae700eba47766d0d907e2b9633a957f19398151111a879563cbe719ddb4a4078dd4ba42ebbf15203d75a4ed3dcd126cb86937222d2ee8bddc973df44435f3f9335f062b7b68c3da300e88bf1013847af1203402a3147b6f7ddab422d29d56fc7dcb8ad7297b04ccc52f7bc5fdd90bf9e36d01902e0e16aa4c387294c1605c6859b40dad12ae28fdfd3250a2e9
g = 2

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        signal.alarm(0)
        main(self.request)

class ReusableTCPServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

def sendMessage(s, msg):
    s.send(msg.encode())

def recieveMessage(s, msg):
    sendMessage(s, msg)
    return s.recv(4096).decode().strip()

def decrypt(encrypted, shared_secret):
    key = hashlib.md5(long_to_bytes(shared_secret)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    message = cipher.decrypt(encrypted)
    return message

def main(s):
    sendMessage(s, DEBUG_MSG + "Generating The Global DH Parameters\n")
    sendMessage(s, DEBUG_MSG + f"g = {g}, p = {p}\n")
    sendMessage(s, DEBUG_MSG + "Calculation Complete\n\n")

    sendMessage(s, DEBUG_MSG + "Generating The Public Key of CPU...\n")
    c = random.randrange(2, p - 1)
    C = pow(g, c, p)
    sendMessage(s, DEBUG_MSG + "Calculation Complete\n")
    sendMessage(s, DEBUG_MSG + "Public Key is: ???\n\n")

    M = recieveMessage(s, "Enter The Public Key of The Memory: ")

    try:
        M = int(M)
    except:
        sendMessage(s, DEBUG_MSG + "Unexpected Error Occured\n")
        exit()

    sendMessage(s, "\n" + DEBUG_MSG + "The CPU Calculates The Shared Secret\n")
    shared_secret = pow(M, c, p)
    sendMessage(s, DEBUG_MSG + "Calculation Complete\n\n")

    encrypted_sequence = recieveMessage(
        s, "Enter The Encrypted Initialization Sequence: ")

    try:
        encrypted_sequence = bytes.fromhex(encrypted_sequence)
        assert len(encrypted_sequence) % 16 == 0
    except:
        sendMessage(s, DEBUG_MSG + "Unexpected Error Occured\n")
        exit()

    sequence = decrypt(encrypted_sequence, shared_secret)

    if sequence == b"Initialization Sequence - Code 0":
        sendMessage(s, "\n" + DEBUG_MSG +
                    "Reseting The Protocol With The New Shared Key\n")
        sendMessage(s, DEBUG_MSG + f"{FLAG}")
    else:
        exit()

if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    server = ReusableTCPServer(("0.0.0.0", 1337), Handler)
    server.serve_forever()
```

Taking a quick look at the code, we can understand what it's doing:
1. We get this really really really big parameter `p`. Using `p` as upper range, it randomly generates `c`
2. We are prompted to enter an integer `M` (if it's not an *int*, an error will be thrown)
3. `shared_secret` is calculated using `M`, `c` and `p`
4. We are prompted to enter a sequence in hexadecimal (we know it because it uses the function `bytes.fromhex()` to convert it to bytes)
5. This sequence gets decrypted with the `decrypt` function we see in the code. It does the following:
	1. hash `shared_secret`
	2. generates the cipher with hash as key
	3. decrypts using the library's method
6. If the decrypted message equals `b"Initialization Sequence - Code 0"`, return the flag

Our objective is then to manage to encrypt this sequence of bytes taking advantage of the fact that we control `M`, which will be used to calculate `shared_secret`, which will end up being the key (`shared_secret` is calculated like `shared_secret = pow(M, c, p)`).

Even though we cannot know the value of `c`, and it might make this seem impossible to solve, what would happen if we indicate that `M=0`? Suddenly it doesn't matter what number `c` is. 
* 0 multiplied by 0 `c` times is still 0
* 0 `mod` `p` is still 0
  
Which basically means... that we know `shared_secret`! It's as easy as 0!

Now we just need to encrypt the sequence of bytes following everything that is done in the `decrypt` function. 
* We will generate the key the same way, since we have access to the `hashlib` library:
```python
key = hashlib.md5(long_to_bytes(shared_secret)).digest()
```

* We will also generate the cipher the same way, since we know it's using the `Crypto.Cipher` library:
```python
cipher = AES.new(key, AES.MODE_ECB)
```

* Since this library (`Crypto.Cipher`) has a `decrypt` method, we will assume it also contains an `encrypt` method which works opposite to `decrypt`:
```python
message = cipher.encrypt(sequence)
```

* Now we managed to encrypt the sequence of bytes, so we are left with `b'\x1a\xf7a1J\x07\xbfy\xf3\x1a\xebS\xbc\x9e\x135\xe1t\x9e\x11B\xb3&\xd8*<)\xac7\xa0B\xbf'`. However, one of the first things the script does when receiving the encrypted message, is to perform `bytes.fromhex(encrypted_sequence)`, so we need to deliver an hexadecimal version of the encrypted message:
```python
message_hex = message.hex()
```

If we put everything together, we are left with the following `script.py`:

```python
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import hashlib

sequence = b"Initialization Sequence - Code 0"
shared_secret = 0

# encrypt
key = hashlib.md5(long_to_bytes(shared_secret)).digest()
cipher = AES.new(key, AES.MODE_ECB)
message = cipher.encrypt(sequence)
message_hex = message.hex()

print(message_hex)
```

We run it, and get the encrypted sequence: `1af761314a07bf79f31aeb53bc9e1335e1749e1142b326d82a3c29ac37a042bf`

Whoop whoop!

Let's try to use it now on the hackthebox instance:

```
└─$ netcat 134.122.103.40 31011
DEBUG MSG - Generating The Global DH Parameters
DEBUG MSG - g = 2, p = 10177459997049772558637057109490700048394574760284564283959324525695097805837401714582821820424475480057537817583807249627119267268524840254542683041588432363128111683358536204391767254517057859973149680238170237977230020947732558089671785239121778309357814575486749623687357688511361367822815452806637006568922401890961240475060822815400430220536180181951862931844638638933951683988349468373510128406899660648258602475728913837826845743111489145006566908004165703542907243208106044538037004824530893555918497937074663828069774495573109072469750423175863678445547058247156187317168731446722852098571735569138516533993
DEBUG MSG - Calculation Complete

DEBUG MSG - Generating The Public Key of CPU...
DEBUG MSG - Calculation Complete
DEBUG MSG - Public Key is: ???

Enter The Public Key of The Memory: 0

DEBUG MSG - The CPU Calculates The Shared Secret
DEBUG MSG - Calculation Complete

Enter The Encrypted Initialization Sequence: 1af761314a07bf79f31aeb53bc9e1335e1749e1142b326d82a3c29ac37a042bf

DEBUG MSG - Reseting The Protocol With The New Shared Key
DEBUG MSG - HTB{7h15_15_cr3@t3d_by_Danb3er_@nd_h@s_c0pyr1gh7_1aws!_!} 
```

BINGO! So the flag is `HTB{7h15_15_cr3@t3d_by_Danb3er_@nd_h@s_c0pyr1gh7_1aws!_!}`