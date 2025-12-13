# ViroScan – Malware Scanner using VirusTotal API

ViroScan is a simple web application that allows users to scan URLs and files for malware using the VirusTotal API. It provides login functionality, scan history storage, and clear result reporting through a user-friendly interface.


# Features

User registration and login

URL scanning

File upload scanning

Detailed scan result display

Scan history page

SQLite database for storing user and scan data

VirusTotal API integration

# System Architecture

ViroScan is built using a client-server architecture.
The client interacts with the browser interface, Flask handles the backend logic, VirusTotal performs the scanning, and SQLite stores the data.

# Technologies Used

Python Flask

HTML, CSS, JavaScript

SQLite

VirusTotal API

Visual Studio Code

# Project Structure
ViroScan/
│── static/
│── templates/
│── database/
│── app.py
│── requirements.txt
│── README.md

# How to Run the Project
# 1. Clone the Repository
git clone https://github.com/sakshi220122/viroScan.git
cd viroScan

# 2. Install Dependencies
pip install -r requirements.txt

# 3. Add Your VirusTotal API Key

Create a .env file in the project folder and add:

VT_API_KEY=your_api_key_here

# 4. Run the Application
python app.py

# 5. Open in Browser

Open:

http://127.0.0.1:5000/

# Testing

The system was tested using:

Unit testing (login, URL scan, file scan)

Integration testing (Flask + database + VirusTotal)

Manual UI testing

All core features performed correctly.

# Security Measures

Password hashing

Input validation

Secured API key

HTTPS support

Authentication for protected pages

# Team Members

Sakshi Umesh Teli (20079303) – UI, backend, API integration, report writing
Hardik Shailesh Rathod (20083974) – Database, testing, screenshots, diagrams

# References

VirusTotal API Documentation

Flask Documentation

SQLite Documentation

# GitHub Repository

https://github.com/sakshi220122/viroScan.git

# Project Video

https://youtu.be/ydDqTS--PSY
