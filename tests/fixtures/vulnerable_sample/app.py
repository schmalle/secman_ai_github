"""Tiny deliberately-insecure web app used as a security-review test fixture.

Contains two intentional, well-known vulnerabilities:
  1. SQL injection — user input concatenated directly into a query.
  2. Hardcoded credential — an API secret committed in source.
"""

import sqlite3

from flask import Flask, request

app = Flask(__name__)

# VULN 2: hardcoded secret credential committed to source control.
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # VULN 1: SQL injection via string concatenation of untrusted input.
    cur.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
    return str(cur.fetchall())


if __name__ == "__main__":
    app.run()
