import streamlit as st
import sqlite3
from datetime import datetime
import time
from pathlib import Path

# Create uploads directory if it doesn't exist
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# Database initialization
def init_db():
    conn = sqlite3.connect('school_messaging.db')
    c = conn.cursor()
    
    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, 
                  role TEXT, full_name TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY, timestamp TEXT, sender TEXT, receiver TEXT,
                  subject TEXT, message TEXT, category TEXT, read INTEGER DEFAULT 0,
                  parent_id INTEGER DEFAULT NULL)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS attachments
                 (id INTEGER PRIMARY KEY, message_id INTEGER, 
                  filename TEXT, data BLOB)''')
    
    conn.commit()
    conn.close()

def hash_password(password):
    """Hash a password for storing."""
    import hashlib
    return hashlib.sha256(str.encode(password)).hexdigest()

def create_user(username, password, role, full_name):
    conn = sqlite3.connect('school_messaging.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password, role, full_name) VALUES (?, ?, ?, ?)',
                  (username, hash_password(password), role, full_name))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

# Message functions
def save_message(sender, receiver, subject, message, category, parent_id=None):
    conn = sqlite3.connect('school_messaging.db')
    c = conn.cursor()
    c.execute('''INSERT INTO messages 
                 (timestamp, sender, receiver, subject, message, category, parent_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (datetime.now().isoformat(), sender, receiver, subject, message, 
               category, parent_id))
    message_id = c.lastrowid
    conn.commit()
    conn.close()
    return message_id

def save_attachment(message_id, file):
    conn = sqlite3.connect('school_messaging.db')
    c = conn.cursor()
    bytes_data = file.getvalue()
    c.execute('INSERT INTO attachments (message_id, filename, data) VALUES (?, ?, ?)',
              (message_id, file.name, bytes_data))
    conn.commit()
    conn.close()

def get_messages(username):
    conn = sqlite3.connect('school_messaging.db')
    c = conn.cursor()
    c.execute('''SELECT m.*, GROUP_CONCAT(a.filename) as attachments
                 FROM messages m
                 LEFT JOIN attachments a ON m.id = a.message_id
                 WHERE m.receiver = ?
                 GROUP BY m.id
                 ORDER BY m.timestamp DESC''',
              (username,))
    messages = c.fetchall()
    conn.close()
    return messages

def mark_as_read(message_id):
    conn = sqlite3.connect('school_messaging.db')
    c = conn.cursor()
    c.execute('UPDATE messages SET read = 1 WHERE id = ?', (message_id,))
    conn.commit()
    conn.close()

def get_thread(message_id):
    conn = sqlite3.connect('school_messaging.db')
    c = conn.cursor()
    c.execute('''SELECT * FROM messages WHERE id = ? OR parent_id = ?''', 
              (message_id, message_id))
    thread = c.fetchall()
    conn.close()
    return thread

# Authentication functions
def login_user(username, password):
    conn = sqlite3.connect('school_messaging.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=? AND password=?',
              (username, hash_password(password)))
    user = c.fetchone()
    conn.close()
    return user

# Main application
def main():
    st.set_page_config(page_title="School Messaging System", page_icon="🏫")
    
    # Initialize database
    init_db()
    
    # Initialize session state
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'signup_mode' not in st.session_state:
        st.session_state.signup_mode = False
    
    # Login/Signup page
    if not st.session_state.logged_in:
        if st.session_state.signup_mode:
            show_signup_page()
        else:
            show_login_page()
        return
    
    # Main application interface
    st.title("🏫 School Messaging System")
    
    # Sidebar navigation
    with st.sidebar:
        st.write(f"Welcome, {st.session_state.full_name}!")
        page = st.radio("📫 Navigation", 
                       ["Inbox", "Compose Message", "Sent Messages"])
        
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.rerun()
    
    if page == "Inbox":
        show_inbox()
    elif page == "Compose Message":
        show_compose()
    else:
        show_sent_messages()

def show_login_page():
    st.title("🏫 School Messaging System - Login")
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        user = login_user(username, password)
        if user:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = user[3]
            st.session_state.full_name = user[4]
            st.rerun()
        else:
            st.error("Invalid username or password")
    
    st.write("Don't have an account?")
    if st.button("Sign Up"):
        st.session_state.signup_mode = True
        st.rerun()

def show_signup_page():
    st.title("🏫 School Messaging System - Sign Up")
    
    full_name = st.text_input("Full Name")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    role = st.selectbox("Role", ["student", "teacher"])
    
    if st.button("Sign Up"):
        if full_name and username and password:
            success = create_user(username, password, role, full_name)
            if success:
                st.success("Account created successfully!")
                st.session_state.signup_mode = False
                st.rerun()
            else:
                st.error("Username already exists. Please choose another.")
        else:
            st.error("Please fill out all fields.")
    
    if st.button("Back to Login"):
        st.session_state.signup_mode = False
        st.rerun()

def show_inbox():
    st.header("📥 Inbox")
    
    # Filter options
    col1, col2 = st.columns(2)
    with col1:
        category_filter = st.selectbox("Filter by category:",
                                     ["All", "Important", "Academic", "General"])
    with col2:
        read_filter = st.selectbox("Filter by status:",
                                 ["All", "Unread", "Read"])
    
    messages = get_messages(st.session_state.username)
    
    if not messages:
        st.info("No messages in your inbox")
        return
    
    for msg in messages:
        if category_filter != "All" and msg[6] != category_filter:
            continue
        if read_filter == "Unread" and msg[7] == 1:
            continue
        if read_filter == "Read" and msg[7] == 0:
            continue
        
        with st.expander(
            f"{'🔵' if not msg[7] else '⚪'} From: {msg[2]} | "
            f"Subject: {msg[4]} | {msg[1][:16]}"
        ):
            if not msg[7]:
                mark_as_read(msg[0])
            
            # Display message thread
            thread = get_thread(msg[0])
            for thread_msg in thread:
                st.write(f"**From:** {thread_msg[2]}")
                st.write(f"**Date:** {thread_msg[1]}")
                st.write(thread_msg[5])
                
                # Display attachments
                if msg[8]:  # attachments column
                    st.write("**Attachments:**")
                    for filename in msg[8].split(','):
                        with open(UPLOAD_DIR / filename, 'rb') as f:
                            st.download_button(
                                f"📎 {filename}",
                                f,
                                filename
                            )
            
            # Reply button
            if st.button(f"Reply", key=f"reply_{msg[0]}"):
                st.session_state.replying_to = msg[0]
                st.session_state.reply_subject = f"Re: {msg[4]}"
                st.session_state.reply_to = msg[2]
                st.rerun()

def show_compose():
    st.header("✍️ Compose Message")
    
    # Get possible recipients based on role
    conn = sqlite3.connect('school_messaging.db')
    c = conn.cursor()
    recipient_role = 'student' if st.session_state.role == 'teacher' else 'teacher'
    c.execute('SELECT full_name FROM users WHERE role = ?', (recipient_role,))
    possible_recipients = [r[0] for r in c.fetchall()]
    conn.close()
    
    # Message form
    if hasattr(st.session_state, 'replying_to'):
        receiver = st.session_state.reply_to
        subject = st.session_state.reply_subject
        reply_to = st.session_state.replying_to
    else:
        receiver = st.selectbox("To:", possible_recipients)
        subject = st.text_input("Subject:")
        reply_to = None
    
    message = st.text_area("Message:")
    category = st.selectbox("Category:", ["General", "Important", "Academic"])
    
    attachment = st.file_uploader("Attach file:", type=['png', 'jpg', 'pdf', 'docx'])
    
    if st.button("Send"):
        if receiver and subject and message:
            message_id = save_message(st.session_state.full_name, receiver, subject, message, category, reply_to)
            if attachment is not None:
                save_attachment(message_id, attachment)
            st.success("Message sent!")
        else:
            st.error("Please fill in all fields.")

def show_sent_messages():
    st.header("📤 Sent Messages")
    
    conn = sqlite3.connect('school_messaging.db')
    c = conn.cursor()
    c.execute('''SELECT m.*, GROUP_CONCAT(a.filename) as attachments
                 FROM messages m
                 LEFT JOIN attachments a ON m.id = a.message_id
                 WHERE sender = ?
                 GROUP BY m.id
                 ORDER BY m.timestamp DESC''',
              (st.session_state.full_name,))
    messages = c.fetchall()
    conn.close()
    
    if not messages:
        st.info("No sent messages.")
        return
    
    for msg in messages:
        with st.expander(
            f"To: {msg[3]} | Subject: {msg[4]} | {msg[1][:16]}"
        ):
            # Display message details
            st.write(f"**To:** {msg[3]}")
            st.write(f"**Date:** {msg[1]}")
            st.write(msg[5])
            
            # Display attachments
            if msg[8]:  # attachments column
                st.write("**Attachments:**")
                for filename in msg[8].split(','):
                    with open(UPLOAD_DIR / filename, 'rb') as f:
                        st.download_button(
                            f"📎 {filename}",
                            f,
                            filename
                        )

# Run the app
if __name__ == "__main__":
    main()
