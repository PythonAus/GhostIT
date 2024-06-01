### GhostIT

GhostIT is a secure messaging application that uses encryption to ensure the privacy and security of messages and files. The application employs both asymmetric and symmetric encryption to protect data during transmission and storage.

---

#### Features
- **Secure messaging with encryption**
- **File encryption and decryption**
- **User authentication and registration**
- **Messages and files are deleted after being decrypted and viewed**
- **Private key encryption client-side with user password**
- **Public key and messages are separated from private keys for enhanced security**
- **Usernames can change every message**
- **Private key password of your choice and change when you like**

---

#### Installation

**Prerequisites**
- Python 3.9+
- PostgreSQL x2 (although one can be used with code modifications)

**Step-by-Step Installation Guide**

1. **Clone the repository**

   ```
   git clone https://github.com/PythonAus/ghost-messenger-v3.git
   cd ghost-messenger-v3
   ```

2. **Create a virtual environment and activate it**

   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install the required packages**

   ```sh
   pip install -r requirements.txt
   ```

4. **Set up the PostgreSQL databases**

   Ensure you have two PostgreSQL databases: one for general data (`DATABASE_URL`) and one for encrypted data (`DATABASE_URL_SEND`).

   **Create the necessary tables in your PostgreSQL databases**

   For `DATABASE_URL`:

   ```sql
   CREATE TABLE IF NOT EXISTS users (
       id SERIAL PRIMARY KEY,
       username VARCHAR(255) NOT NULL UNIQUE,
       password_hash VARCHAR(60) NOT NULL,
       is_verified BOOLEAN DEFAULT FALSE
   );

   CREATE TABLE IF NOT EXISTS messages (
       id SERIAL PRIMARY KEY,
       message TEXT,
       sender_username VARCHAR(255) NOT NULL,
       receiver_username VARCHAR(255) NOT NULL,
       public_key TEXT NOT NULL,
       encrypted_image BYTEA
   );
   ```

   For `DATABASE_URL_SEND`:

   ```sql
   CREATE TABLE IF NOT EXISTS privatekeys (
       id SERIAL PRIMARY KEY,
       sender_username VARCHAR(255) NOT NULL,
       receiver_username VARCHAR(255) NOT NULL,
       encrypted_private_key TEXT NOT NULL
   );

   CREATE TABLE IF NOT EXISTS encrypted_images (
       id SERIAL PRIMARY KEY,
       username VARCHAR(255) NOT NULL,
       encrypted_image BYTEA NOT NULL,
       encrypted_key BYTEA NOT NULL
   );
   ```

5. **Create a .env file in the root directory with the following structure:**

   ```
   .env
   DATABASE_URL_SEND=postgresql://ghost:FAKEPASSWORD@HOSTNAME:PORT/ECT
   DATABASE_URL=postgresql://ghost:FAKEPASSWORD@HOSTNAME:PORT/ECT
   CSRF_SECRET_KEY=your_csrf_secret_key
   PRIVATE_KEY=your_private_key
   SECRET_KEY=your_secret_key
   ```

---

#### Using the Application

**Registration and Login**

1. **Register a new user** by providing a username and password.
2. **Login with your credentials.** Note that only verified users can access the main features. 
   - This is done by the person running the app by manually changing the verified status in the database table `users` or by running `verifyusers.py`.

**Sending a Message**

1. **Compose a Message:**
   - Fill in the sender (which can be any name), receiver (any name), message, and optionally attach a file. 
   - Provide the private key password, which you and the receiver should already know.
2. **Send:**
   - The message and file are encrypted and stored in the database.

**Decrypting and Viewing Messages**

1. **View Messages:**
   - Provide the receiver username and private key password.
2. **Decrypt:**
   - The application decrypts the message and file. Both the message and associated data are then deleted from the database.



#### Security Features

- **Asymmetric Encryption:**
  - RSA is used to encrypt the symmetric key and the message.
- **Symmetric Encryption:**
  - Fernet (symmetric encryption) is used to encrypt files.
- **Private Key Encryption:**
  - The private key is encrypted client-side using a password for added security. The person getting the message must already know the password.
- **Separation of Keys:**
  - Public keys and messages are stored separately from private keys to enhance security.
- **Deletion of Data:**
  - All messages, files, and keys are deleted from the database once they are decrypted and viewed to ensure that data is not retained unnecessarily.
- **Usernames can be changed when sending messages**
# GhostIT
# GhostIT
# GhostIT
