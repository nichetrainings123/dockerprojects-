
import psycopg2
from flask import Flask, request, redirect, session, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "India#201305"

# PostgreSQL database connection details
DB_HOST = "postgres-db"
DB_NAME = "login"
DB_USER = "postgres"
DB_PASSWORD = "India#201305"
DB_PORT = 5432


def get_db():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        port=DB_PORT
    )


# Create the users table if it does not exist
def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    mobile VARCHAR(20),
                    age INTEGER,
                    sex VARCHAR(30)
                )
            """)


HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Python Login Application</title>
    <style>
        body {
            font-family: Arial;
            background: #eef2f7;
            padding: 25px;
        }
        .card {
            max-width: 420px;
            margin: 30px auto;
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 3px 15px #ccc;
        }
        input, select, button {
            width: 100%;
            box-sizing: border-box;
            padding: 12px;
            margin: 8px 0;
        }
        button {
            background: #1769e0;
            color: white;
            border: 0;
            cursor: pointer;
        }
        h2 { text-align: center; }
        .message { color: #c00; }
    </style>
</head>
<body>
<div class="card">
    <h2>{{ title }}</h2>
    <p class="message">{{ message }}</p>
    {{ content|safe }}
</div>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def home():
    mode = request.args.get("mode", "login")
    message = ""

    if request.method == "POST":
        mode = request.form.get("mode", "login")
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    if mode == "register":
                        username = request.form.get("username", "").strip()
                        mobile = request.form.get("mobile", "").strip()
                        age_text = request.form.get("age", "").strip()
                        sex = request.form.get("sex", "")
                        
                        if not username or not email or not password:
                            message = "Username, email and password are required."
                        elif len(password) < 8:
                            message = "Password must be at least 8 characters."
                        else:
                            try:
                                age = int(age_text) if age_text else None
                                if age is not None and not 0 <= age <= 130:
                                    raise ValueError
                            except ValueError:
                                message = "Enter a valid age."
                                age = None

                            if not message:
                                cur.execute("""
                                    INSERT INTO users
                                    (username, email, password, mobile, age, sex)
                                    VALUES (%s, %s, %s, %s, %s, %s)
                                """, (
                                    username,
                                    email,
                                    generate_password_hash(password),
                                    mobile or None,
                                    age,
                                    sex or None
                                ))
                                return redirect("/?mode=login&registered=1")

                    else:
                        cur.execute(
                            "SELECT id, password FROM users WHERE email = %s",
                            (email,)
                        )
                        user = cur.fetchone()

                        if user and check_password_hash(user[1], password):
                            session.clear()
                            session["user_id"] = user[0]
                            return redirect("/?mode=dashboard")

                        message = "Invalid email or password."

        except psycopg2.errors.UniqueViolation:
            message = "Email already registered."
        except psycopg2.Error:
            app.logger.exception("Database connection/query failed")
            message = "Database error. Check application logs."

    if request.args.get("registered") == "1":
        message = "Registration successful. Please log in."

    if mode == "dashboard":
        if "user_id" not in session:
            return redirect("/?mode=login")

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT username, email, mobile, age, sex
                    FROM users WHERE id = %s
                """, (session["user_id"],))
                user = cur.fetchone()

        if not user:
            session.clear()
            return redirect("/?mode=login")

        content = """
        <p><b>Username:</b> {{ u[0] }}</p>
        <p><b>Email:</b> {{ u[1] }}</p>
        <p><b>Mobile:</b> {{ u[2] or '-' }}</p>
        <p><b>Age:</b> {{ u[3] if u[3] is not none else '-' }}</p>
        <p><b>Sex:</b> {{ u[4] or '-' }}</p>
        <a href="/logout">Logout</a>
        """
        return render_template_string(
            HTML, title="User Dashboard", message="",
            content=content, u=user
        )

    if mode == "register":
        title = "Create Account"
        content = """
        <form method="post">
            <input type="hidden" name="mode" value="register">
            <input name="username" placeholder="Username" required>
            <input type="email" name="email" placeholder="Email ID" required>
            <input type="password" name="password"
                   placeholder="Password (minimum 8 characters)"
                   minlength="8" required>
            <input name="mobile" placeholder="Mobile">
            <input type="number" name="age" placeholder="Age"
                   min="0" max="130">
            <select name="sex">
                <option value="">Select sex</option>
                <option>Male</option>
                <option>Female</option>
                <option>Other</option>
                <option>Prefer not to say</option>
            </select>
            <button type="submit">Register</button>
        </form>
        <a href="/?mode=login">Already registered? Login</a>
        """
    else:
        title = "User Login"
        content = """
        <form method="post">
            <input type="hidden" name="mode" value="login">
            <input type="email" name="email" placeholder="Email ID" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <a href="/?mode=register">Create an account</a>
        """

    return render_template_string(
        HTML, title=title, message=message, content=content
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/?mode=login")


if __name__ == "__main__":
    init_db()
    print("Connected to PostgreSQL. Starting Flask application...")
    app.run(host="0.0.0.0", port=5000)
