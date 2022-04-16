## What the actual fuck is this?
It's a chat system that is designed to run on top of TOR and make use of its privacy benefits while providing its own benefits.

## Ok how do I set it up?
1. You need a copy of this project (obviously)
2. You need to run `python3 main.py` and close it after the screen opened
3. You need to give your friend a copy of your `secret/chat_config` and your friend has to give you theirs too
4. You need to merge your own config with it by running `python3 merge.py secret/chat_config YOUR_FRIENDS_CONFIG`
5. You and your friend can now run `python3 main.py` and should be able to communicate. (Warning: it can take up to a minute until you can send a message and both of you have to be online for it to work)

## Ok and how does it work?
1. It sets up a hidden service (have a look at `secret/hostname`)
2. It runs a server that accepts incoming messages
3. The client can send messages to that server

### Names
* node: a hidden service that accepts messages and/or can send messages
* user: a ed25519 keypair
    * nodes and users aren't the same
      * you can have a node without any users, a node with more than one user and a user running on many nodes or even nodes that relay messages

### Message format
* JSON
* format
  * payload: string (is JSON)
    * msg: string
    * type: string (e.g. "text/plain")
    * time: int (unix timestamp)
  * key: string (base85 of the sender's ed25519 public key)
  * sig: string (signature over the raw bytes of payload)

### Send flow
* C>S send public key for X25519 key exchange
* S>C does the same
* C>S sends encrypted message
* C>S closes connection
