#!/usr/bin/env python3
"""
Sample vulnerable Python code designed to trigger multiple CodeGuru Security findings
This file contains intentional security vulnerabilities for testing purposes
"""

import os
import sqlite3
import pickle
import subprocess
import xml.etree.ElementTree as ET
import random
import hashlib
from flask import Flask, request, render_template_string

app = Flask(__name__)

# 1. Hardcoded credentialsss
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
SECRET_TOKEN = "super_secret_token_12345"

# 2. SQL Injection vulnerabilityyy
def get_user_data(user_id):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # Vulnerable: Direct string concatenation in SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchone()
    # Resource leak: connection not closed
    return result

# 3. Command injection vulnerabilityy
def process_file(filename):
    # Vulnerable: Unsanitized input to shell command
    os.system(f"cat {filename} | grep 'important'")
    return "Processing complete"

# 4. Path traversal vulnerability
def read_config_file(config_name):
    # Vulnerable: No path validation
    config_path = f"/app/configs/{config_name}"
    with open(config_path, 'r') as f:
        content = f.read()
    return content

# 5. Insecure deserialization
def load_user_session(session_data):
    # Vulnerable: Unsafe pickle deserialization
    return pickle.loads(session_data)

# 6. XML External Entity (XXE) vulnerability
def parse_user_xml(xml_content):
    # Vulnerable: No protection against XXE attacks
    root = ET.fromstring(xml_content)
    return root.text

# 7. Weak random number generation
def generate_password_reset_token():
    # Vulnerable: Using predictable random
    token = random.randint(100000, 999999)
    return str(token)

# 8. Insecure hash function
def hash_password(password):
    # Vulnerable: Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()

# 9. Flask XSS vulnerability
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Vulnerable: Direct template rendering without escaping
    template = f"<h1>Search results for: {query}</h1>"
    return render_template_string(template)

# 10. Subprocess injection
def backup_database(db_name):
    # Vulnerable: Shell injection in subprocess
    subprocess.call(f"mysqldump {db_name} > backup.sql", shell=True)

# 11. File handle resource leak
def process_log_file(log_path):
    # Vulnerable: File not properly closed
    f = open(log_path, 'r')
    data = f.read()
    # Missing f.close() - resource leak
    return len(data)

# 12. Sensitive data in logs
def authenticate_user(username, password):
    print(f"Login attempt: {username}:{password}")  # Vulnerable: Password in logs
    if username == "admin" and password == DATABASE_PASSWORD:
        return True
    return False

# 13. Unsafe eval usage
def calculate_expression(expr):
    # Vulnerable: Code injection via eval
    return eval(expr)

# 14. LDAP injection potential
def search_user_ldap(username):
    # Vulnerable: Unsanitized LDAP query
    ldap_filter = f"(uid={username})"
    # This would be vulnerable in actual LDAP implementation
    return f"Searching for: {ldap_filter}"

# 15. Non-Pythonic code patterns for improvement suggestions
def process_user_list(users):
    # Non-Pythonic: Manual index iteration instead of enumerate
    result = []
    for i in range(len(users)):
        if users[i]['active'] == True:  # Non-Pythonic: == True comparison
            result.append(users[i]['name'].upper())
    return result

def check_permissions(user_role):
    # Non-Pythonic: Multiple if-elif instead of dict lookup
    if user_role == 'admin':
        permissions = ['read', 'write', 'delete']
    elif user_role == 'editor':
        permissions = ['read', 'write']
    elif user_role == 'viewer':
        permissions = ['read']
    else:
        permissions = []
    return permissions

def format_data(data):
    # Non-Pythonic: String concatenation in loop
    output = ""
    for item in data:
        output = output + str(item) + ","
    return output[:-1]  # Remove trailing comma

def find_max_value(numbers):
    # Non-Pythonic: Manual max finding instead of built-in
    max_val = numbers[0]
    for num in numbers:
        if num > max_val:
            max_val = num
    return max_val

class UserManager:
    # Non-Pythonic: Not using properties or context managers
    def __init__(self):
        self.users = []
        self.connection = None
    
    def get_connection(self):
        if self.connection == None:  # Non-Pythonic: == None instead of is None
            self.connection = sqlite3.connect('users.db')
        return self.connection
    
    def add_user(self, name, email):
        # Non-Pythonic: Manual dict creation instead of using **kwargs
        user = {}
        user['name'] = name
        user['email'] = email
        user['id'] = len(self.users) + 1
        self.users.append(user)

if __name__ == "__main__":
    # More vulnerabilities in main execution
    user_input = input("Enter filename: ")
    process_file(user_input)  # Command injection
    
    config = input("Enter config name: ")
    read_config_file(config)  # Path traversal
    
    # Non-Pythonic: Not using if __name__ == '__main__' properly
    app.run(debug=True, host='0.0.0.0')  # Debug mode in production
