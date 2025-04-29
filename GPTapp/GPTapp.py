import streamlit as st
from openai import OpenAI
from sqlalchemy import create_engine, Table, Column, Integer, String, Text, MetaData, select
import hashlib
import ast
from typing import List, Dict

engine = create_engine("sqlite:///chat_app.db", future=True)
metadata = MetaData()

users = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String, unique=True, nullable=False),
    Column("password_hash", String, nullable=False),
)

chats = Table(
    "chats", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String, nullable=False),
    Column("messages", Text, nullable=False),
)

metadata.create_all(engine)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def user_exists(username: str) -> bool:
    username = username.lower().strip()
    with engine.connect() as conn:
        return conn.execute(select(users).where(users.c.username == username)).first() is not None


def register_user(username: str, password: str) -> str:
    username, password = username.lower().strip(), password.strip()
    if not username or not password:
        return "Username and password cannot be empty."
    if len(username) < 3 or len(username) > 20 or not username.isalnum():
        return "Username must be 3-20 alphanumeric characters."
    if len(password) < 6:
        return "Password must be at least 6 characters."
    if user_exists(username):
        return "Username already taken."
    with engine.begin() as conn:
        conn.execute(users.insert().values(username=username, password_hash=hash_password(password)))
    return ""


def check_credentials(username: str, password: str) -> bool:
    username, password = username.lower().strip(), password.strip()
    with engine.connect() as conn:
        user = conn.execute(select(users).where(users.c.username == username)).fetchone()
        return user is not None and user.password_hash == hash_password(password)


def load_history(username: str) -> List[Dict[str, str]]:
    username = username.lower().strip()
    with engine.connect() as conn:
        record = conn.execute(select(chats).where(chats.c.username == username)).fetchone()
        return ast.literal_eval(record.messages) if record else [{"role": "system", "content": "You are a helpful assistant."}]


def save_history(username: str, messages: List[Dict[str, str]]) -> None:
    username = username.lower().strip()
    with engine.begin() as conn:
        record_exists = conn.execute(select(chats).where(chats.c.username == username)).first()
        if record_exists:
            conn.execute(chats.update().where(chats.c.username == username).values(messages=str(messages)))
        else:
            conn.execute(chats.insert().values(username=username, messages=str(messages)))


def get_response(messages: List[Dict[str, str]], api_key: str) -> str:
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model="gpt-4-1106-preview",
        messages=messages,
        max_tokens=700,
    )
    return response.choices[0].message.content


st.title("GPT-4.1 Chat App with Authentication and Memory")

state_defaults = {
    "page": "login",
    "username": "",
    "signup_err": "",
    "login_err": "",
    "registered": False,
}

for key, val in state_defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val


def signup():
    st.subheader("Create account")
    with st.form("signup_form", clear_on_submit=True):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Register"):
            error = register_user(username, password)
            if error:
                st.session_state.signup_err = error
            else:
                st.session_state.signup_err = ""
                st.session_state.registered = True
                st.session_state.page = "login"
                st.rerun()
    if st.session_state.signup_err:
        st.error(st.session_state.signup_err)
    if st.button("Back to Login"):
        st.session_state.page = "login"
        st.signup_err = ""
        st.rerun()


def login():
    st.subheader("Login")
    if st.session_state.registered:
        st.success("Registration successful. Please log in.")
        st.session_state.registered = False
    with st.form("login_form", clear_on_submit=True):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Login"):
            if check_credentials(username, password):
                st.session_state.username = username.lower().strip()
                st.session_state.page = "chat"
                st.login_err = ""
                st.rerun()
            else:
                st.session_state.login_err = "Invalid username or password."
    if st.session_state.login_err:
        st.error(st.session_state.login_err)
    if st.button("Create an account"):
        st.session_state.page = "signup"
        st.login_err = ""
        st.rerun()


def chat():
    st.write(f"Welcome, **{st.session_state.username}**!")
    if st.button("Logout"):
        st.session_state.page = "login"
        st.session_state.username = ""
        st.session_state.pop("messages", None)
        st.rerun()

    api_key = st.text_input("OpenAI API Key (not stored)", type="password")
    if st.session_state.username and "messages" not in st.session_state:
        st.session_state.messages = load_history(st.session_state.username)

    if "messages" in st.session_state:
        for msg in st.session_state.messages[1:]:
            st.chat_message("user" if msg["role"] == "user" else "assistant").write(msg["content"])

    if api_key:
        user_input = st.chat_input("Send a message:")
        if user_input:
            st.session_state.messages.append({"role": "user", "content": user_input})
            with st.spinner("GPT is typing..."):
                try:
                    reply = get_response(st.session_state.messages, api_key)
                    st.session_state.messages.append({"role": "assistant", "content": reply})
                    save_history(st.session_state.username, st.session_state.messages)
                    st.rerun()
                except Exception as e:
                    st.error(f"Request failed: {e}")
    else:
        st.info("Please enter your OpenAI API key to start chatting.")


PAGES = {"login": login, "signup": signup, "chat": chat}
PAGES[st.session_state.page]()