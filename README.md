# Virex Security System

AI-powered Web Application Firewall and Security Dashboard  
Designed to detect, analyze, and mitigate web attacks in real time.

---

## Overview

Virex is a security platform that combines rule-based detection and machine learning to protect web applications.  
It monitors incoming traffic, detects malicious behavior, and provides a real-time dashboard for analysis and response.

---

## Features

### Security
- Rule-based WAF using regex patterns stored in the database  
- Machine learning detection using Random Forest classifier  
- Rate limiting per IP (100 requests per 60 seconds)  
- Brute force protection with automatic IP blocking  
- CSRF and SSRF detection  
- Scanner detection for sensitive paths  
- IP blacklisting (manual and automatic)  
- Threat logging and audit tracking  

### Dashboard
- Real-time monitoring  
- Attack distribution and timeline visualization  
- Top attacker identification  
- Incident management system  
- Machine learning performance metrics  

---

## Architecture

Each request passes through the following pipeline:

1. Rate limiting  
2. Scanner detection  
3. CSRF and SSRF validation  
4. WAF rule matching  
5. Machine learning classification  

Decision thresholds:
- Block if score ≥ 0.90  
- Monitor if score ≥ 0.70  
- Allow otherwise  

Database: PostgreSQL (Supabase)

---

## Tech Stack

- Backend: Python 3.11, Flask  
- Database: PostgreSQL  
- Machine Learning: scikit-learn (Random Forest)  
- Frontend: JavaScript, Chart.js  
- Authentication: JWT with pbkdf2 password hashing  
- Infrastructure: Docker  

