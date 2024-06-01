--THESE TABLES GO IN THE POSTGRESS SQL DATABASE
--DATABASE_URL TABLE

-- Create the 'users' table to store user details
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(60) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE
);

-- Create the 'messages' table to store messages
CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    message TEXT,
    sender_username VARCHAR(255) NOT NULL,
    receiver_username VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_image BYTEA
);



--THESE GO INTO THE POSTGRESS SQL DATABSE FOR
--DATABASE_URL_SEND

-- Create the 'privatekeys' table to store encrypted private keys
CREATE TABLE IF NOT EXISTS privatekeys (
    id SERIAL PRIMARY KEY,
    sender_username VARCHAR(255) NOT NULL,
    receiver_username VARCHAR(255) NOT NULL,
    encrypted_private_key TEXT NOT NULL
);

-- Create the 'encrypted_images' table to store encrypted images and their associated keys
CREATE TABLE IF NOT EXISTS encrypted_images (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    encrypted_image BYTEA NOT NULL,
    encrypted_key BYTEA NOT NULL
);
