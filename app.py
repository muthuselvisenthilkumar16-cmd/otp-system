import streamlit as st
import secrets
import hashlib
import hmac
import re
import time
from datetime import datetime, timedelta
from db import get_connection


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SecureAuth | OTP Security System",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="expanded"
)


# --------------------------------------------------
# CUSTOM DESIGN
# --------------------------------------------------

st.markdown("""
<style>

.main {
    padding-top: 2rem;
}

.block-container {
    max-width: 900px;
}

.hero {
    padding: 30px;
    border-radius: 18px;
    text-align: center;
    background: linear-gradient(135deg, #111827, #1e293b);
    border: 1px solid #334155;
    margin-bottom: 25px;
}

.hero h1 {
    color: #38bdf8;
    font-size: 42px;
    margin-bottom: 5px;
}

.hero p {
    color: #cbd5e1;
    font-size: 17px;
}

.security-card {
    padding: 18px;
    border-radius: 14px;
    background: #111827;
    border: 1px solid #334155;
    margin: 8px 0;
}

.security-card h4 {
    color: #38bdf8;
}

.status {
    padding: 15px;
    border-radius: 12px;
    background: #052e16;
    border: 1px solid #166534;
    color: #86efac;
}

.otp-box {
    text-align: center;
    padding: 25px;
    border-radius: 15px;
    background: #172554;
    border: 1px solid #2563eb;
}

.footer {
    text-align: center;
    color: #64748b;
    margin-top: 40px;
    font-size: 13px;
}

</style>
""", unsafe_allow_html=True)


# --------------------------------------------------
# PASSWORD HASH
# --------------------------------------------------

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# --------------------------------------------------
# PASSWORD STRENGTH
# --------------------------------------------------

def password_strength(password):

    score = 0

    if len(password) >= 8:
        score += 1

    if re.search(r"[A-Z]", password):
        score += 1

    if re.search(r"[a-z]", password):
        score += 1

    if re.search(r"[0-9]", password):
        score += 1

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1

    if score <= 2:
        return "Weak"

    elif score <= 4:
        return "Medium"

    return "Strong"


# --------------------------------------------------
# REGISTER USER
# --------------------------------------------------

def register_user(username, email, password):

    conn = get_connection()
    cursor = conn.cursor()

    try:

        password_hash = hash_password(password)

        query = """
        INSERT INTO users (username, email, password)
        VALUES (%s, %s, %s)
        """

        cursor.execute(
            query,
            (username.strip(), email.strip(), password_hash)
        )

        conn.commit()

        return True, "Registration successful."

    except Exception:

        return False, "Username or email may already exist."

    finally:

        cursor.close()
        conn.close()


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

def check_login(username, password):

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:

        query = """
        SELECT *
        FROM users
        WHERE username = %s
        """

        cursor.execute(query, (username.strip(),))

        user = cursor.fetchone()

        if user:

            entered_hash = hash_password(password)

            if hmac.compare_digest(
                user["password"],
                entered_hash
            ):
                return user

        return None

    finally:

        cursor.close()
        conn.close()


# --------------------------------------------------
# GENERATE SECURE OTP
# --------------------------------------------------

def generate_otp(user_id):

    otp = str(
        secrets.randbelow(900000) + 100000
    )

    expiry = datetime.now() + timedelta(minutes=2)

    conn = get_connection()
    cursor = conn.cursor()

    try:

        query = """
        UPDATE users
        SET otp = %s,
            otp_expiry = %s,
            otp_attempts = 0
        WHERE id = %s
        """

        cursor.execute(
            query,
            (otp, expiry, user_id)
        )

        conn.commit()

        return otp

    finally:

        cursor.close()
        conn.close()


# --------------------------------------------------
# VERIFY OTP
# --------------------------------------------------

def verify_otp(user_id, entered_otp):

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:

        cursor.execute(
            """
            SELECT otp,
                   otp_expiry,
                   otp_attempts
            FROM users
            WHERE id = %s
            """,
            (user_id,)
        )

        user = cursor.fetchone()

        if not user:
            return False, "User not found."

        if user["otp"] is None:
            return False, "No active OTP. Please request a new OTP."

        if user["otp_attempts"] >= 5:

            cursor.execute(
                """
                UPDATE users
                SET otp = NULL,
                    otp_expiry = NULL
                WHERE id = %s
                """,
                (user_id,)
            )

            conn.commit()

            return False, "Maximum OTP attempts reached."

        if datetime.now() > user["otp_expiry"]:

            cursor.execute(
                """
                UPDATE users
                SET otp = NULL,
                    otp_expiry = NULL
                WHERE id = %s
                """,
                (user_id,)
            )

            conn.commit()

            return False, "OTP expired. Please request a new OTP."

        if not hmac.compare_digest(
            str(entered_otp),
            str(user["otp"])
        ):

            cursor.execute(
                """
                UPDATE users
                SET otp_attempts = otp_attempts + 1
                WHERE id = %s
                """,
                (user_id,)
            )

            conn.commit()

            remaining = 4 - user["otp_attempts"]

            return False, f"Invalid OTP. Attempts remaining: {remaining}"

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

        return True, "OTP verified successfully."

    finally:

        cursor.close()
        conn.close()


# --------------------------------------------------
# SESSION STATE
# --------------------------------------------------

defaults = {
    "page": "login",
    "user": None,
    "temp_user": None,
    "otp": None,
    "otp_created": None
}

for key, value in defaults.items():

    if key not in st.session_state:
        st.session_state[key] = value


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

with st.sidebar:

    st.markdown("## 🔐 SecureAuth")

    st.caption(
        "OTP-Based Cybersecurity Authentication"
    )

    st.divider()

    if st.session_state.user:

        st.success("🟢 Authenticated")

    else:

        st.info("🔵 Authentication required")

    st.divider()

    st.markdown("### 🛡️ Security Controls")

    st.write("✅ Password hashing")
    st.write("✅ Secure OTP generation")
    st.write("✅ OTP expiration")
    st.write("✅ Attempt limitation")
    st.write("✅ Session authentication")
    st.write("✅ Cloud database")
    st.write("✅ Protected secrets")

    st.divider()

    if st.button("📚 Project Overview"):

        st.session_state.page = "about"
        st.rerun()


# --------------------------------------------------
# PROJECT OVERVIEW
# --------------------------------------------------

if st.session_state.page == "about":

    st.markdown("""
    <div class="hero">

    <h1>🔐 SecureAuth</h1>

    <p>
    Secure OTP-Based Authentication System
    </p>

    </div>
    """, unsafe_allow_html=True)

    st.subheader("🎓 Project Objective")

    st.write(
        """
        The objective of this project is to develop a secure
        authentication system using password verification and
        One-Time Password (OTP) authentication.
        
        The system demonstrates important cybersecurity concepts
        including authentication, password protection, OTP security,
        session management and database security.
        """
    )

    st.subheader("🔄 Authentication Process")

    st.code("""
User
 ↓
Username + Password
 ↓
Password Verification
 ↓
Secure 6-Digit OTP
 ↓
2-Minute OTP Timer
 ↓
OTP Verification
 ↓
Authenticated Dashboard
""")

    st.subheader("🛡️ Security Features")

    features = [
        ("Password Hashing",
         "Passwords are stored as cryptographic hashes instead of plain text."),

        ("Secure OTP",
         "OTP values are generated using a cryptographically secure random generator."),

        ("OTP Expiration",
         "Each OTP becomes invalid after two minutes."),

        ("Attempt Limitation",
         "A maximum of five incorrect OTP attempts is permitted."),

        ("Session Authentication",
         "The dashboard is accessible only after successful OTP verification."),

        ("Secret Management",
         "Database credentials are stored using Streamlit Secrets."),

        ("Cloud Database",
         "User authentication data is stored in an Aiven MySQL database.")
    ]

    for title, description in features:

        st.markdown(
            f"""
            <div class="security-card">
            <h4>🛡️ {title}</h4>
            <p>{description}</p>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.subheader("💻 Technologies Used")

    st.write(
        """
        • Python  
        • Streamlit  
        • MySQL  
        • Aiven Cloud  
        • Cryptographic Hashing  
        • OTP Authentication  
        • Session Management
        """
    )

    if st.button("← Back to Login"):

        st.session_state.page = "login"
        st.rerun()

    st.stop()


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

if st.session_state.user:

    user = st.session_state.user

    st.markdown("""
    <div class="hero">

    <h1>🛡️ Security Dashboard</h1>

    <p>Multi-Factor Authentication Successful</p>

    </div>
    """, unsafe_allow_html=True)

    st.success(
        f"Welcome, {user['username']}!"
    )

    st.subheader("👤 Account Information")

    col1, col2 = st.columns(2)

    with col1:

        st.metric(
            "Authentication",
            "Verified"
        )

    with col2:

        st.metric(
            "Security Level",
            "2FA"
        )

    st.write(
        f"**Username:** {user['username']}"
    )

    st.write(
        f"**Email:** {user['email']}"
    )

    st.markdown(
        """
        <div class="status">

        🟢 Account successfully authenticated using
        password + OTP verification.

        </div>
        """,
        unsafe_allow_html=True
    )

    st.subheader("🔒 Active Security Controls")

    col1, col2 = st.columns(2)

    with col1:

        st.write("✅ Password verified")
        st.write("✅ OTP verified")
        st.write("✅ OTP expired after use")

    with col2:

        st.write("✅ Session authenticated")
        st.write("✅ Attempt protection")
        st.write("✅ Secure database")

    st.divider()

    if st.button("🚪 Logout"):

        st.session_state.user = None
        st.session_state.temp_user = None
        st.session_state.otp = None
        st.session_state.otp_created = None
        st.session_state.page = "login"

        st.rerun()

    st.markdown(
        '<div class="footer">SecureAuth • Cybersecurity College Project</div>',
        unsafe_allow_html=True
    )

    st.stop()


# --------------------------------------------------
# REGISTER PAGE
# --------------------------------------------------

if st.session_state.page == "register":

    st.markdown("""
    <div class="hero">

    <h1>📝 Create Account</h1>

    <p>Register for secure OTP authentication</p>

    </div>
    """, unsafe_allow_html=True)

    username = st.text_input(
        "👤 Username",
        placeholder="Enter username"
    )

    email = st.text_input(
        "📧 Email",
        placeholder="Enter email address"
    )

    password = st.text_input(
        "🔑 Password",
        type="password",
        placeholder="Minimum 8 characters"
    )

    if password:

        strength = password_strength(password)

        if strength == "Strong":
            st.success("Password strength: Strong")
        elif strength == "Medium":
            st.warning("Password strength: Medium")
        else:
            st.error("Password strength: Weak")

    confirm_password = st.text_input(
        "🔑 Confirm Password",
        type="password"
    )

    if st.button(
        "Create Secure Account",
        use_container_width=True
    ):

        if not username or not email or not password:

            st.error("Please fill all fields.")

        elif not re.match(
            r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
            email
        ):

            st.error("Enter a valid email address.")

        elif len(password) < 8:

            st.error(
                "Password must contain at least 8 characters."
            )

        elif password_strength(password) == "Weak":

            st.error(
                "Use uppercase, lowercase, numbers and symbols."
            )

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

                time.sleep(1)

                st.session_state.page = "login"
                st.rerun()

            else:

                st.error(message)

    if st.button(
        "← Back to Login",
        use_container_width=True
    ):

        st.session_state.page = "login"
        st.rerun()

    st.stop()


# --------------------------------------------------
# LOGIN PAGE
# --------------------------------------------------

if st.session_state.page == "login":

    st.markdown("""
    <div class="hero">

    <h1>🔐 SecureAuth</h1>

    <p>Two-Factor Authentication System</p>

    </div>
    """, unsafe_allow_html=True)

    st.info(
        "🔒 Your account is protected by password + OTP authentication."
    )

    username = st.text_input(
        "👤 Username",
        placeholder="Enter your username"
    )

    password = st.text_input(
        "🔑 Password",
        type="password",
        placeholder="Enter your password"
    )

    if st.button(
        "🔐 Secure Login",
        use_container_width=True
    ):

        if not username or not password:

            st.error(
                "Please enter username and password."
            )

        else:

            user = check_login(
                username,
                password
            )

            if user:

                otp = generate_otp(user["id"])

                st.session_state.temp_user = user
                st.session_state.otp = otp
                st.session_state.otp_created = datetime.now()
                st.session_state.page = "otp"

                st.rerun()

            else:

                st.error(
                    "Invalid username or password."
                )

    if st.button(
        "📝 Create New Account",
        use_container_width=True
    ):

        st.session_state.page = "register"
        st.rerun()


# --------------------------------------------------
# OTP PAGE
# --------------------------------------------------

elif st.session_state.page == "otp":

    st.markdown("""
    <div class="hero">

    <h1>🔢 OTP Verification</h1>

    <p>Second factor authentication</p>

    </div>
    """, unsafe_allow_html=True)

    st.info(
        "Enter the 6-digit OTP generated for your login."
    )

    # --------------------------------------------------
    # COUNTDOWN
    # --------------------------------------------------

    created = st.session_state.otp_created

    elapsed = (
        datetime.now() - created
    ).total_seconds()

    remaining = max(
        0,
        120 - int(elapsed)
    )

    minutes = remaining // 60
    seconds = remaining % 60

    if remaining > 0:

        st.markdown(
            f"""
            <div class="otp-box">

            <h2>⏱️ OTP expires in</h2>

            <h1>{minutes:02d}:{seconds:02d}</h1>

            </div>
            """,
            unsafe_allow_html=True
        )

        st.progress(
            remaining / 120
        )

    else:

        st.error(
            "⛔ OTP has expired."
        )

    # --------------------------------------------------
    # DEMO OTP
    # --------------------------------------------------

    st.warning(
        f"🎓 DEMO MODE — OTP: {st.session_state.otp}"
    )

    entered_otp = st.text_input(
        "🔢 Enter 6-digit OTP",
        max_chars=6,
        placeholder="123456"
    )

    if st.button(
        "✅ Verify OTP",
        use_container_width=True,
        disabled=remaining == 0
    ):

        success, message = verify_otp(
            st.session_state.temp_user["id"],
            entered_otp
        )

        if success:

            st.session_state.user = (
                st.session_state.temp_user
            )

            st.session_state.temp_user = None
            st.session_state.otp = None
            st.session_state.otp_created = None
            st.session_state.page = "login"

            st.rerun()

        else:

            st.error(message)

    col1, col2 = st.columns(2)

    with col1:

        if st.button(
            "🔄 Resend OTP",
            use_container_width=True
        ):

            new_otp = generate_otp(
                st.session_state.temp_user["id"]
            )

            st.session_state.otp = new_otp
            st.session_state.otp_created = datetime.now()

            st.rerun()

    with col2:

        if st.button(
            "← Cancel Login",
            use_container_width=True
        ):

            st.session_state.otp = None
            st.session_state.temp_user = None
            st.session_state.otp_created = None
            st.session_state.page = "login"

            st.rerun()

    # Automatic countdown refresh
    if remaining > 0:

        time.sleep(1)
        st.rerun()