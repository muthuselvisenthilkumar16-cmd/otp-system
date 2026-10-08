import streamlit as st
import random
from datetime import datetime, timedelta
import hashlib
from db import get_connection

st.set_page_config(
    page_title="Secure OTP Login",
    page_icon="🔐",
    layout="centered"
)

# ---------- Password Hash ----------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# ---------- Register ----------
def register_user(username, email, password):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        password_hash = hash_password(password)

        query = """
        INSERT INTO users (username, email, password)
        VALUES (%s, %s, %s)
        """

        cursor.execute(query, (username, email, password_hash))
        conn.commit()

        return True, "Registration successful!"

    except Exception as e:
        return False, str(e)

    finally:
        cursor.close()
        conn.close()


# ---------- Login ----------
def check_login(username, password):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
    SELECT * FROM users
    WHERE username = %s
    """

    cursor.execute(query, (username,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user:
        if user["password"] == hash_password(password):
            return user

    return None


# ---------- Generate OTP ----------
def generate_otp(user_id):
    otp = str(random.randint(100000, 999999))
    expiry = datetime.now() + timedelta(minutes=2)

    conn = get_connection()
    cursor = conn.cursor()

    query = """
    UPDATE users
    SET otp = %s,
        otp_expiry = %s,
        otp_attempts = 0
    WHERE id = %s
    """

    cursor.execute(query, (otp, expiry, user_id))
    conn.commit()

    cursor.close()
    conn.close()

    return otp


# ---------- Verify OTP ----------
def verify_otp(user_id, entered_otp):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT otp, otp_expiry, otp_attempts FROM users WHERE id = %s",
        (user_id,)
    )

    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return False, "User not found."

    if user["otp_attempts"] >= 5:
        cursor.close()
        conn.close()
        return False, "Too many OTP attempts."

    if datetime.now() > user["otp_expiry"]:
        cursor.close()
        conn.close()
        return False, "OTP expired."

    if entered_otp != user["otp"]:
        cursor.execute(
            """
            UPDATE users
            SET otp_attempts = otp_attempts + 1
            WHERE id = %s
            """,
            (user_id,)
        )
        conn.commit()

        cursor.close()
        conn.close()

        return False, "Invalid OTP."

    cursor.execute(
        """
        UPDATE users
        SET otp = NULL,
            otp_expiry = NULL,
            otp_attempts = 0
        WHERE id = %s
        """,
        (user_id,)
    )

    conn.commit()

    cursor.close()
    conn.close()

    return True, "OTP verified successfully."


# ---------- Session ----------
if "page" not in st.session_state:
    st.session_state.page = "login"

if "user" not in st.session_state:
    st.session_state.user = None

if "otp" not in st.session_state:
    st.session_state.otp = None


# ---------- Dashboard ----------
if st.session_state.user:

    st.title("🏠 Dashboard")

    st.success(
        f"Welcome, {st.session_state.user['username']}!"
    )

    st.write(
        f"Email: {st.session_state.user['email']}"
    )

    st.info("You have successfully logged in using OTP authentication.")

    if st.button("Logout"):
        st.session_state.user = None
        st.session_state.otp = None
        st.session_state.page = "login"
        st.rerun()

    st.stop()


# ---------- Register Page ----------
if st.session_state.page == "register":

    st.title("📝 Create Account")

    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input(
        "Confirm Password",
        type="password"
    )

    if st.button("Register"):

        if not username or not email or not password:
            st.error("Please fill all fields.")

        elif password != confirm_password:
            st.error("Passwords do not match.")

        else:
            success, message = register_user(
                username,
                email,
                password
            )

            if success:
                st.success(message)
                st.session_state.page = "login"
                st.rerun()
            else:
                st.error("Registration failed.")
                st.error(message)

    if st.button("Back to Login"):
        st.session_state.page = "login"
        st.rerun()


# ---------- Login Page ----------
elif st.session_state.page == "login":

    st.title("🔐 Secure OTP Login System")

    st.write("Login using your username and password.")

    username = st.text_input("Username")
    password = st.text_input(
        "Password",
        type="password"
    )

    if st.button("Login"):

        user = check_login(username, password)

        if user:

            otp = generate_otp(user["id"])

            st.session_state.temp_user = user
            st.session_state.otp = otp
            st.session_state.page = "otp"

            st.rerun()

        else:
            st.error("Invalid username or password.")

    if st.button("Create Account"):
        st.session_state.page = "register"
        st.rerun()


# ---------- OTP Page ----------
elif st.session_state.page == "otp":

    st.title("🔢 OTP Verification")

    st.info("Enter the 6-digit OTP.")

    # DEMO ONLY
    st.warning(
        f"Demo OTP: {st.session_state.otp}"
    )

    entered_otp = st.text_input(
        "Enter OTP",
        max_chars=6
    )

    if st.button("Verify OTP"):

        success, message = verify_otp(
            st.session_state.temp_user["id"],
            entered_otp
        )

        if success:

            st.session_state.user = st.session_state.temp_user
            st.session_state.temp_user = None
            st.session_state.otp = None
            st.session_state.page = "login"

            st.success(message)
            st.rerun()

        else:
            st.error(message)

    if st.button("Back to Login"):
        st.session_state.otp = None
        st.session_state.temp_user = None
        st.session_state.page = "login"
        st.rerun()