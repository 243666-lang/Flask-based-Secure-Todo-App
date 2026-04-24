# Secure Todo App

## 📌 Overview

A secure task management web application built with **Flask** as part of my Secure Software Development lab. This application demonstrates implementing authentication, session security, and protection against common web vulnerabilities.

## 🎯 Security Features Implemented

| Feature | Implementation |
|---------|----------------|
| Password Storage | `generate_password_hash()` with salting (werkzeug) |
| SQL Injection Prevention | Parameterized queries (`?` placeholders) |
| CSRF Protection | Flask-WTF with hidden token fields |
| Session Security | HttpOnly cookies, SameSite=Lax, 15-minute timeout |
| Brute Force Protection | Rate limiting: 5 attempts per 60 seconds per IP |
| Session Fixation Prevention | `session.clear()` before setting new session |
| XSS Prevention | Jinja2 auto-escaping + CSP headers |
| Clickjacking Prevention | `X-Frame-Options: DENY` |

## 🛠️ Technologies Used

- Flask (Python)
- SQLite3
- Flask-WTF, WTForms
- Werkzeug (password hashing)
- Bootstrap 5

## 📋 Features

- User Registration with password hashing
- Secure Login with rate limiting
- Task Management (Add, View, Delete)
- Session Management with 15-minute timeout
- CSRF-protected forms

## 🚀 How to Run

### Prerequisites
```bash
Python 3.8+
pip