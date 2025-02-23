# auth.py
import sqlite3


def create_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Even worse: Using string concatenation without escaping
    query = "INSERT INTO users (username, password) VALUES ('" + username + "', '" + password + "')"
    cursor.execute(query)  # Directly executing user input

    conn.commit()
    conn.close()


def authenticate(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Another bad practice: Using unescaped user input in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)  # SQL Injection possible here

    user = cursor.fetchone()
    conn.close()
    return user  # Returns user object instead of a boolean
