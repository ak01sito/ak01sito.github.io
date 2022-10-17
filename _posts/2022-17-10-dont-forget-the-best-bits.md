---
title: Reply Challenges - Don't Forget the Best Bits
date: 2022-10-17 00:28:00 -500
categories: [ctf,crypto]
tags: [reply,aes,cbc,bit_flipping]
---

This post is an attempt to document what I learned during the crypto200 challenge organized by [Reply Challenges](https://challenges.reply.com/tamtamy/home.action) last weekend. It was my first CTF and for sure not the last one!

# Initial View and Idea
To solve the challenge, we had some files to download as well as a URL. On the URL we could find a textbox with a submit button, and a message telling us to submit an encrypted message. 

![website](/images/reply-crypto200-web.png)

When we enter any random message, we get the text `Bad ciphertext provided!`.

Regarding the files, first we had `notes.txt` with the following content:
```
# challenge title
Don't forget the best bits
>
# examples
Cleartext: message%3DFor%20a%20fullfilling%20experience%20embrace%20listen%20to%20new%20music%2E%20Pay%20attention%20to%20details%2C%20titles%20are%20important%2E%20And%20remember%2C%20music%20it%27s%20flipping%20amazing%26user%3Dmario

AES-CBC 128bit Ciphertext: 482c74deadaee362185c315aa10bcd02c96d2417fe3d1adf7fd90da2da95ca16ff9bb7b20b1ed3ac22c93bd3ac7f8d790768379407181f93bbc2c5bde5da5a4e47b400ed0827d815c47b4793349d894a557dd4436a7e2d7967b09faeff6b7037e5ba40202e850c0640414ffd651847bff2fe50ac248ac63cd595339b6fa9ee78f2835d29176d524ab9116894eab6ad5fd56c6600670d1f5bc4e48dfdaed740d1e3b3f1c05a067fbeb69e0a67226755569f185120d5b393131ecd3c209123994135a62d029cc5072264cd6ca306a7d1fc8a63ae9b9675ecace48745f049d5d742639e2df80675ad114938eb641a8b1704
```

We can see a plaintext/cleartext and its respective ciphertext. If we URL decode the plaintext for easier reading, we clearly see that it contains two parameters _message_ and _user_. 

`message=For a fullfilling experience embrace listen to new music. Pay attention to details, titles are important. And remember, music it's flipping amazing&user=mario`

_message_ seems to be giving us a lot of clues about the challenge, so we’ll come back to it when we have more info. _user_ is `mario`. If we enter the ciphertext into the website, we get the text `Thank you for your feedback!`.

The second file (`app.snippet`) contained this:
```
import _aes

if request.method == 'POST':
	ct = request.form.get("ciphertext")
		pt = _aes.decrypt(ct)
		params = parse_qs(unquote(pt))
		message = ''.join(params['message'])
		user = ''.join(params['user'])
		if user == user_flag:
			return make_response(flag,200)
		elif len(message) > 0:
			return make_response("Thank you for your feedback!", 200)


```

Looks like they are showing us a part of what the server does with the data we sent to the previously mentioned website. Basically, it’s taking two parameters (_user_ and _message_, like in the previous file. Coincidence? I don’t think so), and checking if the user equals an unknown `user_flag` variable, in which case it returns the flag. Seems obvious then that we’ll have to craft a text like the one shown before, in which `user = user_flag`. Let’s see the third file and come back to this later.

In the third file (`_aes.py`) we see the following info:
```python
import binascii
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

def encrypt(plaintext):
    aes = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = pad(plaintext.encode('unicode_escape'), AES.block_size, style='pkcs7')
    ciphertext = aes.encrypt(plaintext_padded).hex()
    return ciphertext
    
def decrypt(ciphertext):
    aes = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = aes.decrypt(bytes.fromhex(ciphertext))
    plaintext = unpad(plaintext_padded, AES.block_size, style='pkcs7').decode('unicode_escape')
    return plaintext

```

So they are showing us the encrypt and decrypt methods that the server is using. We obviously don’t see the `key` nor the `iv`, but we get  some important info. 
-   It is using `AES` with `CBC mode`
-   It is using padding `pkcs7`

We have two questions to solve then.

1.  Which user is the correct one that will give us the flag?
2.  How do we craft a modified message which the server can decrypt, if we don’t have the `key` nor the `iv` used by the server?

# GETTING THE CORRECT USER

Let’s first deal with the easier question. In the first file, we got quite an insistent message, telling us to "listen to new music", to "check the titles", and again telling us that music is “flipping amazing”. They also wrote the title ("Don't forget the best bits") again in the file, even though we could see it on the web at any point. Seems like they are trying to tell us something…

![website](/images/reply-crypto200-search.png)

Yup, that’s definitely it. The first idea I’m getting is that the user could be `Franz`, since that’s the name of the band. After looking at the lyrics, though, I see a lot of mentions of `Billy`. So when it's time to insert the user, I'll try both of those.

# UNDERSTANDING THE ALGORITHM

As we saw, they are using `AES` (or Advanced Encryption Standard) with the `CBC mode` (or Cipher Block Chaining mode). The way this algorithm encrypts is first dividing the plaintext in blocks of 16 bytes or characters. The `key` is then used on each block in order to encrypt them. **Yet that’s not everything.** In addition, each block of ciphertext C<sub>i</sub> is used to perform an _XOR_ operation on the next plaintext block P<sub>i+1</sub>before it gets encrypted. This way, two identical blocks would never look the same even though they are encrypted using the same key. In order to _XOR_ the first plaintext block we use an `iv` (Initial Vector). The following picture illustrates this:

![website](/images/reply-crypto200-cbc-encryption.png)

What happens then if the last block is shorter than 16 bytes? Well, that’s when the padding comes into play. It adds the necessary bytes. What's important it’s to notice that with `pkcs7`, if the last block is 16 bytes (which would mean that all blocks are complete and so we don’t need any extra padding), the algorithm **adds padding anyway**, and so we get an extra block which consists of 16 bytes of padding. The plaintext and ciphertext we are given as examples would then look like this:

![website](/images/reply-crypto200-clear-cipher.png)
> First line = plaintext without padding
> Second line = plaintext with padding
> Third line = ciphertext

In order to decrypt, we use the reverse process than to encrypt, so each ciphertext C<sub>i</sub> is used to reveal the plaintext block P<sub>i+1</sub> as shown in the pic:

![website](/images/reply-crypto200-cbc-decryption.png)

# BIT FLIPPING
I’ll admit I was a bit lost at the beginning. How can I generate a new ciphertext with a different username if I’m missing the `key` and the `iv`? It made no sense. I thought about padding oracle. Since the 16 byte padding seemed, in my absolute ignorance on the topic, like a curious thing to have. 

After a while, I remembered the time a good friend of mine solved a crypto problem with something called bit flipping attack… and… that sounds familiar… could it be…

`music it's flipping amazing` 

They wrote this in the first file I read! Ok, it had to be this. I was investigating the bit flipping attack for a while, and came across [this post](https://alicegg.tech/2019/06/23/aes-cbc.html): and I just saw it SO CLEARLY. So let’s explain it a bit.

This attack works when we manage to get into our hands a ciphertext and its respective plaintext (Oh wait, we do!). Since the blocks have a specific length, we know in which block is the data we need/want to modify, and also which block of ciphertext will perform the _XOR_ operation on this data after its decryption. Using our challenge as example, we know that the data is on block C<sub>i+1</sub> (Since we can read it in P<sub>i+1</sub>), and we also know that C<sub>i</sub> will be XORed with it in order to reveal the plaintext P<sub>i+1</sub>.
![website](/images/reply-crypto200-clear-cipher.png)

That means, that we can change some parts of a ciphertext block C<sub>i</sub>, and that will end affecting the result of the next plaintext block P<sub>i+1</sub>.

Due to the way _XOR_ works, if we _XOR_ the original plaintext block P<sub>i+1</sub> (the one containing the user `mario`) with the exact same block with the user we want, we will get the difference of those two. In other words, we will get the exact bits we need to change to `mario` so that it says `billy`. In this case, we have: 

`"g%26user%3Dmario" XOR "g%26user%3Dbilly" = "00000000000000000000000f081e0516"`

Those bits are the ones that the ciphertext block C<sub>i</sub> needs to have different in order to modify P<sub>i+1</sub> while being decrypted. For that, we will now _XOR_ C<sub>i</sub> with the result of the previous _XOR_. So at the end we have

`"00000000000000000000000f081e0516" XOR "35a62d029cc5072264cd6ca306a7d1fc"`

There are two cases when using this attack:
![website](/images/reply-crypto200-bit-flipping.png)

In the green case (ideal case), since we modify the `iv` (which won’t need to be decrypted) we attack and modify directly the first plaintext block, and so we cleanly obtain the result we want. This, of course, is only useful if the data we want to modify is on the first 16 characters of the ciphertext we obtained (and if we can actually see and modify the `iv`). We cannot do either of those things, so this case does not apply to us here. 

In the second case (red), we modify a ciphertext block C<sub>i</sub>, which will be _XOR_ed with the next block and produce the P<sub>i+1</sub> plaintext. Modifying a ciphertext C<sub>i</sub> means that the plaintext P<sub>i</sub> will be completely corrupted and unusable. But what if we do not care about what is written there? Then we could apply the bit flipping attack the same way as if C<sub>i</sub> was the `iv`.

In our case the block C<sub>i</sub> contains part of a message which is completely irrelevant for us (`lipping%20amazin`). Since it doesn’t look like the server will be checking it, we can perform the flipping attack using the second case.
  
# IMPLEMENTATION

Now that we know exactly what to do, let's do it!

First of all, we want to know **which exact bits we need to flip in P<sub>i+1</sub>** so that instead of `mario`, the user is either `franz` or `billy`. At the end the user ended up being `billy`, so I will use it as value for the user for the explanation. To know the bits that need to be different, we need to _XOR_ the two plaintext block messages:
```python
def xor_messages(a,b,size=32):
    # messages must be in hexadecimal like "9bc423909ac569b5016525cb4b2660b5"
    bina = bin(int(a,16))[2:]
    binb = bin(int(b,16))[2:]
    y = int(bina,2)^int(binb,2)
    return hex(y)[2:].zfill(size)

current_message = "g%26user%3Dmario"
wanted_message = "g%26user%3Dbilly"

hex_current_message = current_message.encode('utf-8').hex()
hex_wanted_message = wanted_message.encode('utf-8').hex()

diff_bits = xor_messages(hex_current_message,hex_wanted_message)

```

And then, we _XOR_ those bits to the ciphertext block C<sub>i</sub>. In this case, due to the extra padding block explained before, that was the third to last block. 

```python
cipher_blocks = [ciphertext[i:i+32] for i in range(0,len(ciphertext), 32)]
wanted_block = cipher_blocks[12]

bit_flipping = xor_messages(wanted_block, diff_bits)

result = ''.join(cipher_blocks[:12]) + bit_flipping + ''.join(cipher_blocks[-2:]
```

When we execute the script we get the new ciphertext: `482c74deadaee362185c315aa10bcd02c96d2417fe3d1adf7fd90da2da95ca16ff9bb7b20b1ed3ac22c93bd3ac7f8d790768379407181f93bbc2c5bde5da5a4e47b400ed0827d815c47b4793349d894a557dd4436a7e2d7967b09faeff6b7037e5ba40202e850c0640414ffd651847bff2fe50ac248ac63cd595339b6fa9ee78f2835d29176d524ab9116894eab6ad5fd56c6600670d1f5bc4e48dfdaed740d1e3b3f1c05a067fbeb69e0a67226755569f185120d5b393131ecd3c209123994135a62d029cc5072264cd6cac0eb9d4ea8a63ae9b9675ecace48745f049d5d742639e2df80675ad114938eb641a8b1704
`
Finally, we just need to send it to the website and get our flag: 
![website](/images/reply-crypto200-flag.png)

Whoooop whoooop!

<div style="padding: 15px; border: 1px solid transparent; border-color: transparent; margin-bottom: 20px; border-radius: 4px; color: #a94442; background-color: #f2dede; border-color: #ebccd1;">
Initially I coded the script so that it would perform the bit flipping on the last block (the padding one). Since I though it made sense that I could change it since it was not relevant... Next time let's make sure you understand how the algorithm works before flipping things...
</div>

Here you can see the whole script I used:
```python
# --------- DATA -------------

block_size = 16 # 16 byes = 16 characters
cipher_block_size = 32

cleartext = "message%3DFor%20a%20fullfilling%20experience%20embrace%20listen%20to%20new%20music%2E%20Pay%20attention%20to%20details%2C%20titles%20are%20important%2E%20And%20remember%2C%20music%20it%27s%20flipping%20amazing%26user%3Dmario"

# even though the cleartext has 14 blocks, the ciphertext will have 15, since the last block is 16 bytes long, and so the padding adds a new block of 16 characters
ciphertext = "482c74deadaee362185c315aa10bcd02c96d2417fe3d1adf7fd90da2da95ca16ff9bb7b20b1ed3ac22c93bd3ac7f8d790768379407181f93bbc2c5bde5da5a4e47b400ed0827d815c47b4793349d894a557dd4436a7e2d7967b09faeff6b7037e5ba40202e850c0640414ffd651847bff2fe50ac248ac63cd595339b6fa9ee78f2835d29176d524ab9116894eab6ad5fd56c6600670d1f5bc4e48dfdaed740d1e3b3f1c05a067fbeb69e0a67226755569f185120d5b393131ecd3c209123994135a62d029cc5072264cd6ca306a7d1fc8a63ae9b9675ecace48745f049d5d742639e2df80675ad114938eb641a8b1704"


# ---------- FLIPPING -------------
def xor_messages(a,b,size=32):
    # messages must be in hexadecimal like "9bc423909ac569b5016525cb4b2660b5"
    bina = bin(int(a,16))[2:]
    binb = bin(int(b,16))[2:]
    y = int(bina,2)^int(binb,2)
    return hex(y)[2:].zfill(size)
    

cipher_blocks = [ciphertext[i:i+cipher_block_size] for i in range(0,len(ciphertext), cipher_block_size)]
wanted_block = cipher_blocks[12]

current_message = cleartext[-block_size:] # g%26user%3Dmario
hex_current_message = current_message.encode('utf-8').hex()

possible_messages = ["g%26user%3Dfranz", "g%26user%3Dbilly"]

for wanted_message in possible_messages:
    hex_wanted_message = wanted_message.encode('utf-8').hex()

    diff_bits = xor_messages(hex_current_message,hex_wanted_message)
    bit_flipping = xor_messages(wanted_block, diff_bits)

    result = ''.join(cipher_blocks[:12]) + bit_flipping + ''.join(cipher_blocks[-2:])

    print(result)
    print("\n\n")
```

I learned a lot solving this challenge and wanted to document the whole process and the new knowledge. So grateful to [Reply Challenges](https://challenges.reply.com/tamtamy/home.action) for an amazing event!