import sqlite3
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import pickle
import os
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
from email.mime.text import MIMEText
import base64
import logging
import random

# Configure logging to record application events and errors
logging.basicConfig(filename='library.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = 'your_secret_key' # Replace with a strong, unique secret key

# Define the OAuth 2.0 scopes for Gmail API. This scope allows sending emails.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def get_gmail_service():
    """
    Initializes and returns a Google Gmail API service object.
    It handles OAuth 2.0 authentication flow, including loading existing tokens
    or initiating a new authorization flow if necessary.
    """
    try:
        creds = None
        # Check if a token file exists from a previous authentication
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        
        # If no valid credentials, or if they are expired and refreshable, refresh them
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                # If credentials.json is missing, log an error and flash a message
                if not os.path.exists('credentials.json'):
                    flash('Gmail credentials file (credentials.json) missing. Email functionality will not work.', 'error')
                    logging.error('Gmail credentials file missing.')
                    return None
                
                # Initiate a new OAuth 2.0 flow for desktop applications
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                # Run a local server to handle the OAuth 2.0 callback
                creds = flow.run_local_server(port=0)
                
                # Save the new credentials for future use
                with open('token.pickle', 'wb') as token:
                    pickle.dump(creds, token)
        
        # Build and return the Gmail API service
        return build('gmail', 'v1', credentials=creds)
    except Exception as e:
        # Log and flash any errors during Gmail service initialization
        flash(f'Failed to initialize Gmail service: {str(e)}. Check credentials.json and internet connection.', 'error')
        logging.error(f'Failed to initialize Gmail service: {str(e)}')
        return None

def send_email(to_email, subject, body):
    """
    Sends an email using the Gmail API.
    
    Args:
        to_email (str): The recipient's email address.
        subject (str): The subject of the email.
        body (str): The content of the email.
        
    Returns:
        bool: True if the email was sent successfully, False otherwise.
    """
    try:
        service = get_gmail_service()
        if not service:
            return False # Cannot send email if service is not available
        
        # Create a MIMEText message
        message = MIMEText(body)
        message['to'] = to_email
        message['from'] = 'devakarikalan2021@gmail.com'  # IMPORTANT: Replace with your Gmail address
        message['subject'] = subject
        
        # Encode the message to base64url format required by Gmail API
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
        
        # Send the email
        service.users().messages().send(userId='me', body={'raw': raw}).execute()
        logging.info(f'Email sent to {to_email}: "{subject}"')
        return True
    except Exception as e:
        # Log and flash any errors during email sending
        flash(f'Error sending email to {to_email}: {str(e)}', 'error')
        logging.error(f'Error sending email to {to_email}: {str(e)}')
        return False

def generate_custom_id(table_name, id_column):
    """
    Generates a unique custom ID for database records.
    The ID format is "cg" followed by 4 random digits (e.g., "cg1234").
    Ensures uniqueness by checking against existing IDs in the specified table.
    """
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        while True:
            new_id = f"cg{random.randint(1000, 9999)}"
            c.execute(f"SELECT {id_column} FROM {table_name} WHERE {id_column} = ?", (new_id,))
            if not c.fetchone(): # If no existing record with this ID, it's unique
                return new_id
    finally:
        conn.close()

def init_db():
    """
    Initializes the SQLite database and creates necessary tables if they don't exist.
    Also inserts a default 'admin' user if one doesn't already exist.
    """
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        
        # Create 'users' table
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT
        )''')
        
        # Create 'books' table
        c.execute('''CREATE TABLE IF NOT EXISTS books (
            book_id TEXT PRIMARY KEY,
            title TEXT,
            author TEXT,
            total_copies INTEGER,
            available_copies INTEGER
        )''')
        
        # Create 'borrow' table to track book borrowings
        c.execute('''CREATE TABLE IF NOT EXISTS borrow (
            borrow_id TEXT PRIMARY KEY,
            user_id TEXT,
            book_id TEXT,
            borrow_date TEXT,
            due_date TEXT,
            return_date TEXT,
            fine INTEGER
        )''')
        
        # Create 'system_info' table for application-specific settings/data
        c.execute('''CREATE TABLE IF NOT EXISTS system_info (
            key TEXT PRIMARY KEY,
            value TEXT
        )''')
        
        # Insert a default admin user if not already present
        admin_id = generate_custom_id('users', 'id') # Generate ID for admin
        c.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (?, ?, ?, ?, ?)",
                  (admin_id, 'admin', generate_password_hash('admin123'), 'admin@example.com', 'admin'))
        conn.commit()
        logging.info("Database initialized and default admin user ensured.")
    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {str(e)}")
    finally:
        conn.close()

def update_fines():
    """
    Calculates and updates fines for overdue books.
    Fines are calculated at ₹10 per day overdue.
    This function is called periodically and before displaying fine-related pages.
    """
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        today = datetime.now().date()
        
        # Select all unreturned borrowed books
        c.execute("SELECT borrow_id, due_date, fine FROM borrow WHERE return_date IS NULL")
        borrows = c.fetchall()
        
        for borrow in borrows:
            borrow_id, due_date_str, current_fine = borrow
            try:
                due = datetime.strptime(due_date_str, '%Y-%m-%d').date()
                days_overdue = max(0, (today - due).days) # Calculate days overdue (0 if not overdue)
                new_fine = days_overdue * 10 # ₹10 per day
                
                # Update fine only if it has changed
                if new_fine != current_fine:
                    c.execute("UPDATE borrow SET fine = ? WHERE borrow_id = ?", 
                              (new_fine, borrow_id))
            except ValueError as e:
                logging.error(f"Error parsing due_date for borrow_id {borrow_id}: {str(e)}")
                continue # Skip to the next borrow if date parsing fails
        conn.commit()
        logging.info("Fines updated successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error in update_fines: {str(e)}")
    finally:
        conn.close()

def send_reminder_emails(due_soon_only=False):
    """
    Sends reminder emails to users for books that are due soon or overdue.
    
    Args:
        due_soon_only (bool): If True, only sends reminders for books due soon (within 3 days).
                              If False, sends for both due soon and overdue books.
    """
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        today = datetime.now().date()
        reminder_threshold_days = 3 # Books due within 3 days are considered 'due soon'
        reminder_threshold = today + timedelta(days=reminder_threshold_days)
        
        # Select unreturned books for non-admin users that are due by the reminder threshold
        c.execute('''SELECT b.borrow_id, b.user_id, b.book_id, b.due_date, b.fine, bk.title, u.email, u.username
                     FROM borrow b
                     JOIN books bk ON b.book_id = bk.book_id
                     JOIN users u ON b.user_id = u.id
                     WHERE b.return_date IS NULL AND u.role = 'user' 
                     AND b.due_date <= ?''', (reminder_threshold.isoformat(),))
        borrows = c.fetchall()
        
        email_count = 0
        for borrow in borrows:
            borrow_id, user_id, book_id, due_date_str, fine, book_title, email, username = borrow
            try:
                due = datetime.strptime(due_date_str, '%Y-%m-%d').date()
                
                subject = ""
                body = ""

                if due_soon_only:
                    # If only due_soon_only is True, only send for books that are due in the future but within the threshold
                    if due >= today and due <= reminder_threshold:
                        subject = f"Reminder: Return Book '{book_title}'"
                        body = f"Dear {username},\n\nThis is a reminder that the book '{book_title}' is due on {due_date_str}. Please return it on time to avoid fines.\n\nLibrary Management System"
                    else:
                        continue # Skip if not within the 'due soon' window for due_soon_only mode
                else:
                    # For regular scheduled runs, send for both overdue and due soon
                    if due < today:
                        # Book is overdue
                        subject = f"Overdue Book Alert: '{book_title}'"
                        body = f"Dear {username},\n\nThe book '{book_title}' was due on {due_date_str}. Your current fine is ₹{fine}. Please return it promptly to avoid further fines.\n\nLibrary Management System"
                    else:
                        # Book is due soon
                        subject = f"Reminder: Return Book '{book_title}'"
                        body = f"Dear {username},\n\nThis is a reminder that the book '{book_title}' is due on {due_date_str}. Please return it on time to avoid fines.\n\nLibrary Management System"
                
                # Attempt to send the email
                if send_email(email, subject, body):
                    email_count += 1
                    logging.info(f"Reminder email sent to {email} for book '{book_title}' (Borrow ID: {borrow_id})")
                else:
                    logging.warning(f"Failed to send reminder email to {email} for book '{book_title}' (Borrow ID: {borrow_id})")
            except ValueError as e:
                logging.error(f"Error parsing due_date for borrow_id {borrow_id}: {str(e)}")
                continue # Continue to the next borrow record
            except Exception as e:
                logging.error(f"Error processing borrow_id {borrow_id} for email: {str(e)}")
                continue # Catch any other unexpected errors during email processing
        
        # Update system information about the last reminder run
        current_time = datetime.now().isoformat()
        c.execute("INSERT OR REPLACE INTO system_info (key, value) VALUES (?, ?)",
                  ('last_reminder_run', current_time))
        c.execute("INSERT OR REPLACE INTO system_info (key, value) VALUES (?, ?)",
                  ('last_reminder_email_count', str(email_count)))
        
        # Calculate and store the next scheduled run time
        next_run = (datetime.now() + timedelta(hours=12)).isoformat()
        c.execute("INSERT OR REPLACE INTO system_info (key, value) VALUES (?, ?)",
                  ('next_reminder_run', next_run))
        conn.commit()
        logging.info(f"Reminder emails process completed: {email_count} emails sent. Next scheduled run: {next_run}")
    except sqlite3.Error as e:
        logging.error(f"Database error in send_reminder_emails: {str(e)}")
    except Exception as e:
        logging.error(f"Unexpected error in send_reminder_emails: {str(e)}")
    finally:
        conn.close()

# Initialize and start the background scheduler for automatic tasks
scheduler = BackgroundScheduler()
# Schedule send_reminder_emails to run every 12 hours
scheduler.add_job(func=lambda: send_reminder_emails(), trigger='interval', hours=12)
scheduler.start()
# Register a cleanup function to shut down the scheduler when the app exits
atexit.register(lambda: scheduler.shutdown())

@app.route('/')
def index():
    """Redirects to the login page."""
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role'] # 'user' or 'admin'
        user_id = generate_custom_id('users', 'id')
        try:
            conn = sqlite3.connect('library.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (id, username, password, email, role) VALUES (?, ?, ?, ?, ?)",
                      (user_id, username, generate_password_hash(password), email, role))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            logging.info(f"User registered: {username} (ID: {user_id}) with role {role}")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
            logging.warning(f"Failed registration attempt: Username {username} already exists")
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn = sqlite3.connect('library.db')
            c = conn.cursor()
            c.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            if user and check_password_hash(user[2], password):
                # Store user information in session upon successful login
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[3]
                logging.info(f"User logged in: {username} (ID: {user[0]}) with role {user[3]}")
                if user[3] == 'admin':
                    return redirect(url_for('admin_home'))
                return redirect(url_for('user_home'))
            flash('Invalid username or password.', 'error')
            logging.warning(f"Failed login attempt for username: {username}")
        finally:
            conn.close()
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logs out the current user by clearing the session."""
    username = session.get('username', 'Unknown')
    session.clear() # Clear all session data
    flash('Logged out successfully.', 'success')
    logging.info(f"User logged out: {username}")
    return redirect(url_for('login'))

@app.route('/admin/home')
def admin_home():
    """Admin dashboard displaying overdue books, system info, and user management links."""
    # Ensure only admin users can access this page
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Access denied. Please log in as an administrator.', 'error')
        logging.warning(f"Access denied to admin_home for user: {session.get('username', 'Unknown')}")
        return redirect(url_for('login'))
    
    update_fines() # Update fines before displaying the page
    
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        today = datetime.now().date()
        due_soon_date = (today + timedelta(days=3)).isoformat() # Books due within 3 days
        
        # Fetch books that are due soon or overdue (for admin overview)
        c.execute('''SELECT b.borrow_id, b.user_id, b.book_id, b.borrow_date, b.due_date, b.return_date, bk.title, u.username
                     FROM borrow b
                     JOIN books bk ON b.book_id = bk.book_id
                     JOIN users u ON b.user_id = u.id
                     WHERE b.return_date IS NULL AND b.due_date <= ?''', (due_soon_date,))
        due_soon = c.fetchall() # This will include both due soon and overdue books
        
        # Fetch all non-admin users
        c.execute("SELECT id, username, email, role FROM users WHERE role != 'admin'")
        users = c.fetchall()
        
        # Fetch system information about reminder runs
        c.execute("SELECT value FROM system_info WHERE key = 'last_reminder_run'")
        last_reminder = c.fetchone()
        last_reminder_time = last_reminder[0] if last_reminder else 'Never'
        
        c.execute("SELECT value FROM system_info WHERE key = 'last_reminder_email_count'")
        email_count = c.fetchone()
        last_reminder_email_count = int(email_count[0]) if email_count else 0
        
        c.execute("SELECT value FROM system_info WHERE key = 'next_reminder_run'")
        next_reminder = c.fetchone()
        next_reminder_time = next_reminder[0] if next_reminder else 'Unknown'
        
        return render_template('admin_home.html', due_soon=due_soon, users=users, 
                               last_reminder_time=last_reminder_time, 
                               last_reminder_email_count=last_reminder_email_count,
                               next_reminder_time=next_reminder_time)
    finally:
        conn.close()

@app.route('/admin/trigger_reminders')
def trigger_reminders():
    """
    Manually triggers sending reminder emails for books due soon.
    (This is separate from the automatic scheduled job).
    """
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Access denied.', 'error')
        logging.warning(f"Access denied to trigger_reminders for user: {session.get('username', 'Unknown')}")
        return redirect(url_for('login'))
    
    send_reminder_emails(due_soon_only=True) # Send only 'due soon' reminders on manual trigger
    flash('Due soon reminder emails triggered for students/faculty.', 'success')
    logging.info("Manual due soon reminder emails triggered by admin")
    return redirect(url_for('admin_home'))

@app.route('/admin/book_management')
def book_management():
    """Displays a list of all books for administrative management."""
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Access denied.', 'error')
        logging.warning(f"Access denied to book_management for user: {session.get('username', 'Unknown')}")
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        c.execute("SELECT * FROM books")
        books = c.fetchall()
        return render_template('book_management.html', books=books)
    finally:
        conn.close()

@app.route('/admin/add_user', methods=['GET', 'POST'])
def admin_add_user():
    """Allows an admin to add new users (students/faculty)."""
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Access denied.', 'error')
        logging.warning(f"Access denied to admin_add_user for user: {session.get('username', 'Unknown')}")
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        user_id = generate_custom_id('users', 'id')
        try:
            conn = sqlite3.connect('library.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (id, username, password, email, role) VALUES (?, ?, ?, ?, ?)",
                      (user_id, username, generate_password_hash(password), email, role))
            conn.commit()
            flash('User added successfully.', 'success')
            logging.info(f"User added by admin: {username} (ID: {user_id}) with role {role}")
            return redirect(url_for('admin_home'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
            logging.warning(f"Failed to add user: Username {username} already exists")
        finally:
            conn.close()
    return render_template('add_user.html')

@app.route('/admin/delete_user/<user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    """Allows an admin to delete a user, preventing deletion of admins or users with active borrows."""
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Access denied.', 'error')
        logging.warning(f"Access denied to delete_user for user: {session.get('username', 'Unknown')}")
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        # Fetch user details, ensuring it's not an admin user
        c.execute("SELECT id, username, email, role FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        user = c.fetchone()
        if not user:
            flash('User not found or cannot delete an administrator account.', 'error')
            logging.warning(f"Failed to delete user: User ID {user_id} not found or is admin")
            return redirect(url_for('admin_home'))
        
        # Check for active borrows before deletion
        c.execute("SELECT COUNT(*) FROM borrow WHERE user_id = ? AND return_date IS NULL", (user_id,))
        active_borrows = c.fetchone()[0]
        if active_borrows > 0:
            flash('Cannot delete user with active borrowed books. Please ensure all books are returned first.', 'error')
            logging.warning(f"Failed to delete user {user_id}: Active borrows exist ({active_borrows} books)")
            return redirect(url_for('admin_home'))
        
        if request.method == 'POST':
            c.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            flash('User deleted successfully.', 'success')
            logging.info(f"User deleted: {user[1]} (ID: {user_id})")
            return redirect(url_for('admin_home'))
        return render_template('delete_user.html', user=user)
    finally:
        conn.close()

@app.route('/admin/add_book', methods=['GET', 'POST'])
def add_book():
    """Allows an admin to add a new book to the library."""
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Access denied.', 'error')
        logging.warning(f"Access denied to add_book for user: {session.get('username', 'Unknown')}")
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        total_copies = int(request.form['total_copies'])
        book_id = generate_custom_id('books', 'book_id')
        try:
            conn = sqlite3.connect('library.db')
            c = conn.cursor()
            c.execute("INSERT INTO books (book_id, title, author, total_copies, available_copies) VALUES (?, ?, ?, ?, ?)",
                      (book_id, title, author, total_copies, total_copies))
            conn.commit()
            flash('Book added successfully.', 'success')
            logging.info(f"Book added: '{title}' by {author} (ID: {book_id}, Copies: {total_copies})")
            return redirect(url_for('book_management'))
        finally:
            conn.close()
    return render_template('add_book.html')

@app.route('/admin/update_book/<book_id>', methods=['GET', 'POST'])
def update_book(book_id):
    """Allows an admin to update details of an existing book."""
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Access denied.', 'error')
        logging.warning(f"Access denied to update_book for user: {session.get('username', 'Unknown')}")
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        c.execute("SELECT * FROM books WHERE book_id = ?", (book_id,))
        book = c.fetchone()
        if not book:
            flash('Book not found.', 'error')
            logging.warning(f"Book not found for update: {book_id}")
            return redirect(url_for('book_management'))
        if request.method == 'POST':
            title = request.form['title']
            author = request.form['author']
            total_copies = int(request.form['total_copies'])
            
            # Calculate available copies based on current borrows
            c.execute("SELECT COUNT(*) FROM borrow WHERE book_id = ? AND return_date IS NULL", (book_id,))
            borrowed = c.fetchone()[0]
            
            # Ensure total_copies is not less than currently borrowed copies
            if total_copies < borrowed:
                flash(f'Total copies cannot be less than currently borrowed copies ({borrowed}).', 'error')
                logging.warning(f"Attempted to set total copies ({total_copies}) less than borrowed ({borrowed}) for book {book_id}")
                return render_template('update_book.html', book=book)

            available_copies = total_copies - borrowed
            
            c.execute("UPDATE books SET title = ?, author = ?, total_copies = ?, available_copies = ? WHERE book_id = ?",
                      (title, author, total_copies, available_copies, book_id))
            conn.commit()
            flash('Book updated successfully.', 'success')
            logging.info(f"Book updated: '{title}' (ID: {book_id}, Total copies: {total_copies})")
            return redirect(url_for('book_management'))
        return render_template('update_book.html', book=book)
    finally:
        conn.close()

@app.route('/admin/delete_book/<book_id>', methods=['GET', 'POST'])
def delete_book(book_id):
    """Allows an admin to delete a book, preventing deletion if copies are currently borrowed."""
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Access denied.', 'error')
        logging.warning(f"Access denied to delete_book for user: {session.get('username', 'Unknown')}")
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        c.execute("SELECT * FROM books WHERE book_id = ?", (book_id,))
        book = c.fetchone()
        if not book:
            flash('Book not found.', 'error')
            logging.warning(f"Book not found for deletion: {book_id}")
            return redirect(url_for('book_management'))
        
        # Check if any copies are currently borrowed
        c.execute("SELECT COUNT(*) FROM borrow WHERE book_id = ? AND return_date IS NULL", (book_id,))
        active_borrows = c.fetchone()[0]
        if active_borrows > 0:
            flash(f'Cannot delete book. {active_borrows} copies are currently borrowed.', 'error')
            logging.warning(f"Failed to delete book {book_id}: {active_borrows} copies are currently borrowed")
            return redirect(url_for('book_management'))

        if request.method == 'POST':
            c.execute("DELETE FROM books WHERE book_id = ?", (book_id,))
            conn.commit()
            flash('Book deleted successfully.', 'success')
            logging.info(f"Book deleted: '{book[1]}' (ID: {book_id})")
            return redirect(url_for('book_management'))
        return render_template('delete_book.html', book=book)
    finally:
        conn.close()

@app.route('/admin/borrow_book', methods=['GET', 'POST'])
def borrow_book():
    """Allows an admin to record a book borrowing by a user."""
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Access denied.', 'error')
        logging.warning(f"Access denied to borrow_book for user: {session.get('username', 'Unknown')}")
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        # Fetch non-admin users and available books
        c.execute("SELECT id, username, role FROM users WHERE role != 'admin'")
        users = c.fetchall()
        c.execute("SELECT book_id, title, author, available_copies FROM books WHERE available_copies > 0")
        books = c.fetchall()
        
        if request.method == 'POST':
            user_id = request.form['user_id']
            book_id = request.form['book_id']
            
            # Check if the user has already borrowed this specific book and not returned it
            c.execute('''SELECT borrow_id FROM borrow 
                         WHERE user_id = ? AND book_id = ? AND return_date IS NULL''', 
                         (user_id, book_id))
            if c.fetchone():
                flash('This user has already borrowed this book and has not returned it. Cannot borrow again.', 'error')
                logging.warning(f"Failed borrow attempt: User {user_id} already has an active borrow for book {book_id}")
                return redirect(url_for('borrow_book'))
            
            # Check for available copies
            c.execute('SELECT available_copies FROM books WHERE book_id = ?', (book_id,))
            available_copies_result = c.fetchone()
            if not available_copies_result or available_copies_result[0] <= 0:
                flash('No copies available for this book.', 'error')
                logging.warning(f"Failed borrow attempt: No copies available for book {book_id}")
                return redirect(url_for('borrow_book'))
            
            borrow_id = generate_custom_id('borrow', 'borrow_id')
            borrow_date = datetime.now().date().isoformat()
            due_date = (datetime.now().date() + timedelta(days=7)).isoformat() # Due in 7 days
            
            c.execute("INSERT INTO borrow (borrow_id, user_id, book_id, borrow_date, due_date, return_date, fine) VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (borrow_id, user_id, book_id, borrow_date, due_date, None, 0))
            c.execute("UPDATE books SET available_copies = available_copies - 1 WHERE book_id = ?", (book_id,))
            conn.commit()
            flash('Book borrowed successfully.', 'success')
            logging.info(f"Book borrowed: User {user_id}, Book {book_id} (Borrow ID: {borrow_id})")
            return redirect(url_for('admin_home'))
        return render_template('borrow_book.html', users=users, books=books)
    finally:
        conn.close()

@app.route('/admin/borrow_list')
def borrow_list():
    """Displays a list of all currently borrowed books for admin review."""
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Access denied.', 'error')
        logging.warning(f"Access denied to borrow_list for user: {session.get('username', 'Unknown')}")
        return redirect(url_for('login'))
    update_fines() # Update fines before showing the list
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        # Fetch all currently borrowed books with user and book details
        c.execute('''SELECT b.borrow_id, b.user_id, b.book_id, b.borrow_date, b.due_date, b.return_date, b.fine, bk.title, u.username
                     FROM borrow b
                     JOIN books bk ON b.book_id = bk.book_id
                     JOIN users u ON b.user_id = u.id
                     WHERE b.return_date IS NULL''') # Only show unreturned books
        borrows = c.fetchall()
        return render_template('borrow_list.html', borrows=borrows)
    finally:
        conn.close()

@app.route('/admin/return_book/<borrow_id>')
def return_book(borrow_id):
    """Allows an admin to mark a book as returned and finalize any associated fine."""
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Access denied.', 'error')
        logging.warning(f"Access denied to return_book for user: {session.get('username', 'Unknown')}")
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        # Get book_id and fine for the specified borrow record
        c.execute("SELECT book_id, fine FROM borrow WHERE borrow_id = ?", (borrow_id,))
        result = c.fetchone()
        if not result:
            flash('Borrow record not found.', 'error')
            logging.warning(f"Borrow record not found for return: {borrow_id}")
            return redirect(url_for('borrow_list'))
        book_id, fine = result
        
        # Update return date and increment available copies
        c.execute("UPDATE borrow SET return_date = ? WHERE borrow_id = ?",
                  (datetime.now().date().isoformat(), borrow_id))
        c.execute("UPDATE books SET available_copies = available_copies + 1 WHERE book_id = ?", (book_id,))
        conn.commit()
        flash(f'Book returned successfully. Final fine: ₹{fine}.', 'success')
        logging.info(f"Book returned: Borrow ID {borrow_id}, Final fine: ₹{fine}")
        return redirect(url_for('borrow_list'))
    finally:
        conn.close()

@app.route('/admin/fine_management', methods=['GET', 'POST'])
def fine_management():
    """Displays and manages fines for overdue books."""
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Access denied.', 'error')
        logging.warning(f"Access denied to fine_management for user: {session.get('username', 'Unknown')}")
        return redirect(url_for('login'))
    update_fines() # Ensure fines are up-to-date
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        # Fetch all unreturned books with outstanding fines
        c.execute('''SELECT b.borrow_id, b.user_id, b.book_id, b.due_date, b.fine, bk.title, u.username
                     FROM borrow b
                     JOIN books bk ON b.book_id = bk.book_id
                     JOIN users u ON b.user_id = u.id
                     WHERE b.return_date IS NULL AND b.fine > 0''')
        fines = c.fetchall()
        
        if request.method == 'POST':
            borrow_id = request.form['borrow_id']
            # Mark fine as paid (set fine to 0)
            c.execute("UPDATE borrow SET fine = 0 WHERE borrow_id = ?", (borrow_id,))
            conn.commit()
            flash('Fine marked as paid.', 'success')
            logging.info(f"Fine marked as paid: Borrow ID {borrow_id}")
            return redirect(url_for('fine_management'))
        return render_template('fine_management.html', fines=fines)
    finally:
        conn.close()

@app.route('/admin/email_alert/<borrow_id>', methods=['GET', 'POST'])
def email_alert(borrow_id):
    """Allows an admin to send a custom email alert for a specific borrowed book."""
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Access denied.', 'error')
        logging.warning(f"Access denied to email_alert for user: {session.get('username', 'Unknown')}")
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        # Fetch borrow, book, and user details for the email
        c.execute('''SELECT b.borrow_id, b.user_id, b.book_id, b.borrow_date, b.due_date, b.return_date, bk.title, u.username, u.email
                     FROM borrow b
                     JOIN books bk ON b.book_id = bk.book_id
                     JOIN users u ON b.user_id = u.id
                     WHERE b.borrow_id = ?''', (borrow_id,))
        borrow = c.fetchone()
        if not borrow:
            flash('Borrow record not found.', 'error')
            logging.warning(f"Borrow record not found for email alert: {borrow_id}")
            return redirect(url_for('admin_home'))
        
        if request.method == 'POST':
            subject = request.form['subject']
            body = request.form['body']
            to_email = borrow[8] # Email address of the user
            
            if send_email(to_email, subject, body):
                flash(f'Email sent successfully to {to_email}.', 'success')
                logging.info(f"Manual email sent by admin: Borrow ID {borrow_id}, To: {to_email}, Subject: '{subject}'")
            return redirect(url_for('admin_home'))
        return render_template('email_alert.html', borrow=borrow)
    finally:
        conn.close()

@app.route('/user/home')
def user_home():
    """User dashboard displaying their borrowed books and total fines."""
    if 'user_id' not in session:
        flash('Please login to access your dashboard.', 'error')
        logging.warning("Access denied to user_home: No user_id in session")
        return redirect(url_for('login'))
    update_fines() # Update fines before displaying user's home page
    try:
        conn = sqlite3.connect('library.db')
        c = conn.cursor()
        # Fetch currently borrowed books for the logged-in user
        c.execute('''SELECT b.borrow_id, b.user_id, b.book_id, b.borrow_date, b.due_date, b.return_date, b.fine, bk.title
                     FROM borrow b
                     JOIN books bk ON b.book_id = bk.book_id
                     WHERE b.user_id = ? AND b.return_date IS NULL''', (session['user_id'],))
        borrows = c.fetchall()
        
        # Calculate total fines for the user
        total_fines = sum(borrow[6] for borrow in borrows)
        
        # Fetch all available books for the user to browse
        c.execute("SELECT * FROM books WHERE available_copies > 0")
        books = c.fetchall()
        
        return render_template('user_home.html', borrows=borrows, books=books, total_fines=total_fines)
    finally:
        conn.close()

@app.route('/oauth2callback')
def oauth2callback():
    """
    Handles the callback from Google's OAuth 2.0 authorization server.
    This route is crucial for the initial Gmail API authentication.
    """
    try:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        # Set the redirect URI to match what Google expects
        flow.redirect_uri = url_for('oauth2callback', _external=True)
        logging.info(f"OAuth redirect_uri: {flow.redirect_uri}") # Log for debugging
        
        # Fetch the token using the authorization response from the URL
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)
        
        creds = flow.credentials
        # Save the credentials for future use
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
        
        flash('Gmail authentication successful. You can now send emails.', 'success')
        logging.info("Gmail OAuth authentication successful")
        return redirect(url_for('admin_home'))
    except Exception as e:
        flash(f'OAuth error during callback: {str(e)}. Please ensure credentials.json is correct and try again.', 'error')
        logging.error(f"OAuth error during callback: {str(e)}")
        return redirect(url_for('admin_home'))

if __name__ == '__main__':
    init_db() # Initialize the database when the application starts
    # Determine debug mode from environment variable, default to True for development
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    app.run(debug=debug_mode, port=5000) # Run the Flask app on port 5000
