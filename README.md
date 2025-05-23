# 🔓 Website Hacking – Admin Panel Access (DVWA Lab)

### 📁 Project Overview

This project demonstrates how to identify and exploit common web application vulnerabilities to gain unauthorized access to an admin panel. All tests were conducted ethically in a controlled environment using [DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web Application), running on a local virtual machine.

> 🚨 **Disclaimer:** This project was performed strictly for educational purposes and in a secure lab environment. Never conduct unauthorized testing on real systems.

---

### 🎯 Objective

* Identify and exploit common web vulnerabilities:

  * SQL Injection
  * Command Injection
  * Cross-Site Scripting (XSS)
  * Login Bypass
* Gain access to a simulated admin panel
* Provide screenshots, steps, and recommendations for mitigation

---

### 🛠️ Environment Setup

| Component    | Details                                  |
| ------------ | ---------------------------------------- |
| OS           | Kali Linux VM (VMware)                   |
| Web App      | DVWA (PHP/MySQL-based vulnerable app)    |
| Server Stack | Apache, PHP, MariaDB                     |
| Browser      | Firefox                                  |
| Tools Used   | Terminal, Browser, Burp Suite (optional) |

---

## 🔍 Vulnerabilities Exploited

### 1️⃣ SQL Injection – Login Bypass

* **Module:** `SQL Injection`

* **Steps:**

  1. Accessed vulnerable login page.
  2. Entered the following credentials:

     ```sql
     Username: admin' OR '1'='1
     Password: anything
     ```
  3. Logged in successfully.

* **Impact:** Authenticated without knowing valid credentials.

* **Screenshot:**
  ![SQL Injection Success](screenshots/sql-injection.png)

* **Mitigation:**

  * Use parameterized queries (prepared statements)
  * Input validation and sanitization
  * Disable detailed SQL error messages

---

### 2️⃣ Command Injection

* **Module:** `Command Execution`

* **Steps:**

  1. Submitted IP and command:

     ```
     127.0.0.1 && whoami
     ```
  2. Output showed system-level command executed.

* **Impact:** Remote command execution via input field.

* **Screenshot:**
  ![Command Injection](screenshots/command-injection.png)

* **Mitigation:**

  * Use whitelisting for allowed inputs
  * Escape special characters
  * Avoid system calls from user input

---

### 3️⃣ Cross-Site Scripting (XSS)

* **Module:** `Reflected XSS`

* **Steps:**

  1. Injected JavaScript in URL/form input:

     ```html
     <script>alert('XSS')</script>
     ```
  2. Script executed in the browser.

* **Impact:** Execution of arbitrary JS in the user's browser.

* **Screenshot:**
  ![XSS Popup](screenshots/xss.png)

* **Mitigation:**

  * Encode output
  * Use frameworks with built-in XSS protection
  * Implement Content Security Policy (CSP)

---

### 4️⃣ Admin Panel Access – Login Bypass

* **Steps:**

  1. Visited default login path: `http://localhost/dvwa/login.php`
  2. Used SQLi to bypass login:

     ```sql
     Username: ' OR '1'='1 --
     Password: anything
     ```
  3. Gained access to admin-level features.

* **Impact:** Full backend access without credentials.

* **Screenshot:**
  ![Admin Panel Access](screenshots/admin-panel.png)

* **Mitigation:**

  * Secure authentication using prepared statements
  * Implement account lockout for brute-force attempts
  * Use multi-factor authentication (MFA)

---

## 🔐 General Recommendations

| Area           | Recommendation                                           |
| -------------- | -------------------------------------------------------- |
| Input Handling | Validate and sanitize all user inputs (server-side)      |
| Authentication | Use MFA, account lockout, and encrypted password storage |
| Secure Coding  | Avoid using system calls, use secure frameworks          |
| Headers        | Add security headers (CSP, X-Frame-Options, etc.)        |
| Logging        | Log authentication attempts and anomalies                |
| Access Control | Enforce least privilege, protect admin URLs              |

---

## 💬 Reflections

This lab simulated real-world attacks on insecure web applications. The ease with which basic input manipulation compromised login systems, executed commands, and triggered script injection shows the **critical importance of secure coding** and proper validation practices.

---

## 📚 What I Learned

* Hands-on exploitation of common vulnerabilities
* Importance of sanitizing user inputs
* How misconfigurations can lead to privilege escalation
* Steps to mitigate risks in real-world scenarios

---

## 📎 Related Tools & Resources

* [DVWA GitHub Repo](https://github.com/digininja/DVWA)
* [OWASP Top 10](https://owasp.org/www-project-top-ten/)
* [Kali Linux](https://www.kali.org/)
* [Burp Suite](https://portswigger.net/burp)
* [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)

---

Date created: 23/05/2025
