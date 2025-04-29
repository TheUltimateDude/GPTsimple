import streamlit as st
from openai import OpenAI
import sqlalchemy as sa
from sqlalchemy import create_engine, Table, Column, Integer, String, Text, MetaData
import hashlib
import ast
from typing import List, Dict

# ------------------- DATABASE SETUP -------------------
engine = create_engine('sqlite:///chat_app.db')
metadata = MetaData()

users = Table(
    'users', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('username', String, unique=True, nullable=False),
    Column('password_hash', String, nullable=False)
)

chats = Table(
    'chats', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('username', String, nullable=False),
    Column('messages', Text, nullable=False)
)
metadata.create_all(engine)

# ------------------- AUTH FUNCTIONS -------------------
def hash_password(password: str) -> str:
    """Hash a password for storing."""
    return hashlib.sha256(password.encode()).hexdigest()

def check_credentials(username: str, password: str) -> bool:
    """Validate username and password against DB."""
    if not username or not password:
        return False
    with engine.connect() as conn:
        res = conn.execute(sa.select(users).where(users.c.username == username)).fetchone()
        if res and res["password_hash"] == hash_password(password):
            return True
        return False

def user_exists(username: str) -> bool:
    """Check if a username is already taken."""
    with engine.connect() as conn:
        res = conn.execute(sa.select(users).where(users.c.username == username)).fetchone()
        return bool(res)

def register_user(username: str, password: str) -> str:
    """Register a new user. Returns empty string if success, else an error message."""
    if not username or not password:
        return "Username and password cannot be empty."
    if len(username) < 3 or len(username) > 20:
        return "Username must be 3-20 characters."
    if not username.isalnum():
        return "Username only allows letters and numbers."
    if len(password) < 6:
        return "Password must be at least 6 characters."
    if user_exists(username):
        return "Username is already taken."
    with engine.connect() as conn:
        conn.execute(users.insert().values(username=username, password_hash=hash_password(password)))
    return ""

# ------------------- MEMORY FUNCTIONS -------------------
def load_history(username: str) -> List[Dict[str, str]]:
    """Load chat history from DB."""
    with engine.connect() as conn:
        res = conn.execute(sa.select(chats).where(chats.c.username == username)).fetchone()
        if res:
            return ast.literal_eval(res['messages'])
        else:
            return [{"role": "system", "content": "You are a helpful assistant."}]

def save_history(username: str, messages: List[Dict[str, str]]) -> None:
    """Save chat history to DB."""
    with engine.connect() as conn:
        exists = conn.execute(sa.select(chats).where(chats.c.username == username)).first()
        if exists:
            conn.execute(chats.update().where(chats.c.username == username).values(messages=str(messages)))
        else:
            conn.execute(chats.insert().values(username=username, messages=str(messages)))

# ------------------- OPENAI FUNCTION -------------------
def get_response(messages: List[Dict[str, str]], api_key: str) -> str:
    """
    Query OpenAI API and return reply.
    """
    client = OpenAI(api_key=api_key)
    chat_response = client.chat.completions.create(
        model="gpt-4-1106-preview",  # Or your preferred GPT-4.1 endpoint
        messages=messages,
        max_tokens=700
    )
    return chat_response.choices[0].message.content

# ------------------- STREAMLIT UI -------------------
st.title("GPT-4.1 Chat App with Robust Sign Up/Login & Memory")

if "page" not in st.session_state:
    st.session_state.page = "login"
if "username" not in st.session_state:
    st.session_state.username = ""
if "signup_error" not in st.session_state:
    st.session_state.signup_error = ""
if "login_error" not in st.session_state:
    st.session_state.login_error = ""

def signup_page() -> None:
    """Render the sign-up page UI."""
    st.subheader("Sign up for a new account")
    with st.form("signup_form", clear_on_submit=False):
        new_username = st.text_input("Choose a username", key="signup_user")
        new_password = st.text_input("Choose a password", type="password", key="signup_pass")
        submit = st.form_submit_button("Register")
        if submit:
            error = register_user(new_username.strip(), new_password)
            if error:
                st.session_state.signup_error = error
            else:
                st.success("Registration successful. Please log in.")
                st.session_state.signup_error = ""
                st.session_state.page = "login"
                st.experimental_rerun()
    if st.session_state.signup_error:
        st.error(st.session_state.signup_error)
    if st.button("Back to login"):
        st.session_state.page = "login"
        st.session_state.signup_error = ""
        st.experimental_rerun()

def login_page() -> None:
    """Render the login page UI."""
    st.subheader("Login")
    with st.form("login_form", clear_on_submit=False):
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")
        submitted = st.form_submit_button("Login")
        if submitted:
            if check_credentials(username.strip(), password):
                st.session_state.username = username.strip()
                st.session_state.page = "chat"
                st.session_state.login_error = ""
                st.experimental_rerun()
            else:
                st.session_state.login_error = "Invalid username or password."
    if st.session_state.login_error:
        st.error(st.session_state.login_error)
    if st.button("Go to Signup"):
        st.session_state.page = "signup"
        st.session_state.login_error = ""
        st.experimental_rerun()

def chat_page() -> None:
    """Render the chat UI and interactions."""
    st.write(f"Welcome, **{st.session_state.username}**!")
    if st.button("Logout"):
        st.session_state.page = "login"
        st.session_state.username = ""
        st.session_state.pop("messages", None)
        st.experimental_rerun()

    api_key = st.text_input("Your OpenAI API Key (never stored)", type="password")
    if st.session_state.username and "messages" not in st.session_state:
        st.session_state["messages"] = load_history(st.session_state.username)

    if "messages" in st.session_state:
        for msg in st.session_state.messages[1:]:
            align = "user" if msg["role"] == "user" else "assistant"
            st.chat_message(align).write(msg["content"])

    if api_key:
        user_input = st.chat_input("Send a message:")
        if user_input:
            st.session_state.messages.append({"role": "user", "content": user_input})

            with st.spinner("GPT is responding..."):
                try:
                    reply = get_response(st.session_state.messages, api_key)
                    st.session_state.messages.append({"role": "assistant", "content": reply})
                    save_history(st.session_state.username, st.session_state.messages)
                    st.rerun()
                except Exception as e:
                    st.error("Request failed: " + str(e))
    else:
        st.info("Please enter your OpenAI API key to start chatting.")

if st.session_state.page == "login":
    login_page()
elif st.session_state.page == "signup":
    signup_page()
elif st.session_state.page == "chat":
    chat_page()