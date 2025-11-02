
🧾 Assignment Information
**Name:** Khizar Qureshi  
**Roll No:** 22i-2745  
**Section:** FTA  
**Assignment No:** 2  
**Course:** Cybersecurity for FinTech 

## 📋 Overview
**Easy Cash** is a secure, Streamlit-based lending platform developed as part of the *Cybersecurity for FinTech* course.  
It demonstrates the implementation of secure coding practices in financial web applications and allows for **20 manual cybersecurity tests**.

The project focuses on areas such as authentication, encryption, input validation, and secure error handling.


## 🎯 Objectives
- Apply **secure coding principles** in Python web applications.
- Implement features that allow **manual cybersecurity testing**.
- Understand and test vulnerabilities like **SQL Injection, XSS, weak passwords, and session hijacking**.

---

## 🌐 Theme & Design
**Lending Platform:** Easy Cash  
**Color Scheme:** Green & White  
**Built Using:** Python, Streamlit, SQLite, bcrypt, and Fernet encryption.

---

## ⚙️ Core Features Implemented
| Feature | Description | Security Focus |
|----------|--------------|----------------|
| **User Registration & Login** | User accounts stored with bcrypt password hashing | Authentication & password security |
| **Password Validation** | Enforces strong password rules (≥8 chars, digit, symbol) | Password strength enforcement |
| **Input Validation** | Prevents SQL injection & XSS via sanitization and parameterized queries | Input protection |
| **Session Management** | Tracks login/logout & expires sessions after 5 mins inactivity | Session control |
| **Data Encryption** | Encrypts loan amount using Fernet | Confidentiality & data protection |
| **Error Handling** | Prevents stack trace or sensitive info leaks | Information leakage protection |
| **Audit Logs** | Logs all user actions securely | Integrity & traceability |
| **Profile Update Page** | Edit user email with validation | Access control testing |
| **File Upload Validation** | Restricts file types (png, jpg, pdf, txt) and max 2MB | File-based attack protection |

---

## 🧪 Manual Cybersecurity Tests (20 Total)
Below are the manual tests designed for evaluation of Easy Cash:
1. Input Validation – SQL Injection  
2. Password Strength Enforcement  
3. Special Character Input (XSS)  
4. Unauthorized Access (without login)  
5. Session Expiry after 5 mins  
6. Logout Functionality  
7. Data Confidentiality (check hashed/encrypted data)  
8. File Upload Validation  
9. Error Message Leakage  
10. Input Length Validation (>500 chars)  
11. Duplicate User Registration  
12. Number Field Validation  
13. Password Match Check  
14. Data Modification Attempt  
15. Email Validation  
16. Login Attempt Lockout (5 fails)  
17. Secure Error Handling (forced exception)  
18. Encrypted Record Check  
19. Input Encoding (emoji/unicode)  
20. Empty Field Submission


## 🔐 Security Highlights
- Passwords hashed using **bcrypt**  
- Loan amounts encrypted using **Fernet**  
- **Parameterized SQL queries** prevent injection  
- **HTML escaping** prevents XSS attacks  
- **Account lockout** after 5 failed logins  
- **Safe error handling** (no stack traces shown)  
- **Session timeout** after 5 minutes  




