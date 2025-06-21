# Secure Client-Server Messaging System

This project implements a secure messaging system using RSA public-key cryptography. It allows users to send and receive encrypted, digitally signed messages via a centralized server. Messages are delivered once the recipient logs in.

## 🔐 Features

- RSA key pair generation for users (`.pub` and `.prv` files)
- MD5-hashed user identification
- Message encryption and decryption using RSA
- Digital signature for message authenticity and integrity
- Secure message storage and deferred delivery
- Base64-encoded messages and signatures for transport

## 📁 Project Structure

```
.
├── src/com/project/cyber/
│   ├── Client.java          # Client application
│   ├── Server.java          # Server handling message exchange
│   └── RSAKeyGen.java       # Utility for RSA key pair generation
├── alice.pub / .prv         # Alice’s public/private keys
├── bob.pub / .prv           # Bob’s public/private keys
├── server.pub / .prv        # Server’s key pair
├── .gitignore
└── README.md
```

## 🛠️ Compilation & Running

### 1. Generate RSA Keys
```bash
javac src/com/project/cyber/RSAKeyGen.java
java -cp src com.project.cyber.RSAKeyGen alice
java -cp src com.project.cyber.RSAKeyGen bob
java -cp src com.project.cyber.RSAKeyGen server
```

### 2. Compile All Classes
```bash
javac src/com/project/cyber/*.java
```

### 3. Start the Server
```bash
java -cp src com.project.cyber.Server 12345
```

### 4. Start a Client (in a new terminal)
```bash
java -cp src com.project.cyber.Client localhost 12345 alice
```

## (Optional) 

Start another client as bob to simulate message exchange.

## 💬 Usage Flow

1. Client connects to the server using host, port, and user ID.
2. Client sends hashed user ID to server.
3. Server sends unread encrypted messages, which the client decrypts and verifies.
4. Client can send a new message to another user.
5. Message is encrypted using the server’s public key and signed with the client’s private key.
6. Server decrypts, verifies, and stores the message for the intended recipient.
7. Recipient receives the message on next login.

## 🧪 Example

1. Alice sends a message to Bob.
2. Server stores the encrypted message and timestamp.
3. Bob logs in later and retrieves the message.
4. Signature is verified, and the message is decrypted and shown to bob.

## ⚠️ Notes

1. The project uses 2048-bit RSA keys.
2. Key files are stored as <userid>.pub and <userid>.prv in the root directory.
3. Ensure keys are present before running the client/server.

## 📜 License

This project is intended for academic use and demonstration purposes only.
