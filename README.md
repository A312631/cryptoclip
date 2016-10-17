# cryptoclip
ComboCrypt is a high-strength asymmetrical encryption scheme

cryptoclip provides a command-line tool to encrypt/decrypt text from your clipboard with ComboCrypt

### Cloning
```
git clone --recursive https://github.com/samrankin1/cryptoclip.git
```

&nbsp;
### Usage Tutorial

#### Generating keys:
Before sending or receiving encrypted messages, one must generate a personal key pair.
```
python cryptoclip.py generate [myname]
```

#### Sending a message:
To send a message to someone, they must first provide you with a copy of their **public** key (*.pubkey*) -- after that, you can encrypt messages that only they will be able to decrypt.
```
python cryptoclip.py encrypt [theirname]
```
This will copy the encrypted message to your clipboard, which you can send to the recipient via any means. The contents cannot be read or altered in transit, and only the holder of the recipient's key may decrypt it.

#### Receiving a message:
To receive an encrypted message, the sender must provide you with an encrypted message block that was made out to *your* public key. To decrypt the content, you must your your **private** key.
```
python cryptoclip.py decrypt [myname]
```
This will decrypt the message and copy the result to your clipboard.
