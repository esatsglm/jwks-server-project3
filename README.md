# 🔐 JWKS Server – Project 3

This project extends a basic JWKS server by adding security and user management features.  
It includes AES encryption for private keys, user registration, authentication logging, and rate limiting.

---

## 🚀 Features

### 🔑 AES Encryption
- Private keys in SQLite are encrypted using AES (Fernet)
- Encryption key comes from environment variable: NOT_MY_KEY

---

### 👤 User Registration
Endpoint:
POST /register

Request:
{"username":"example","email":"example@mail.com"}

Response:
{"password":"generated-uuid"}

- Password is hashed using Argon2

---

### 🔐 Authentication
Endpoint:
POST /auth

- Returns JWT token
- Supports login with username/password

---

### 📝 Authentication Logging
Each /auth request logs:
- IP address
- timestamp
- user ID

---

### 🚦 Rate Limiting
- 10 requests per second
- Exceeding returns:
{"error":"Too Many Requests"}

---

## 🗄️ Database Tables

keys:
- kid
- key
- exp

users:
- id
- username
- password_hash
- email
- date_registered
- last_login

auth_logs:
- id
- request_ip
- request_timestamp
- user_id

---

## ⚙️ Setup

Install:
pip install flask pyjwt cryptography argon2-cffi

Set key (Windows):
set NOT_MY_KEY=mysecretkey123

Run:
python app.py

---

## 🔗 Endpoints

GET /.well-known/jwks.json  
POST /register  
POST /auth  

---

## 📸 Screenshots

### Register
![Register](screenshots/register.png)

### Auth
![Auth](screenshots/auth.png)

### Rate Limit
![Rate Limit](screenshots/rate_limit.png)

### JWKS
![JWKS](screenshots/jwks.png)

---

## 🧠 Overview

This project demonstrates:
- AES encryption
- Secure password hashing (Argon2)
- JWT authentication
- Rate limiting
- Logging

---

## 👨‍💻 Author
Esat Saglam