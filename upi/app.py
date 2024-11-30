from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import pandas as pd
import joblib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Load the fraud detection model and label encoders
model = joblib.load('fraud_detection_model.pkl')
label_encoders = joblib.load('label_encoders.pkl')

# Email configurations
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_FROM = 'daminmain@gmail.com'
EMAIL_PASSWORD = 'kpqtxqskedcykwjz'  # App password

# Database connection function
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database
def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        email TEXT NOT NULL,
                        transaction_limit REAL NOT NULL DEFAULT 100000,
                        last_limit_update DATE NOT NULL DEFAULT (DATE('now'))
                    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS transactions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        transaction_id INTEGER NOT NULL,
                        amount REAL NOT NULL,
                        location TEXT NOT NULL,
                        payment_method TEXT NOT NULL,
                        transaction_status TEXT NOT NULL,
                        transaction_type TEXT NOT NULL,
                        frequent_transactions INTEGER NOT NULL,
                        high_refunds INTEGER NOT NULL,
                        prediction TEXT NOT NULL
                    )''')
    conn.close()

# Preprocess new data for prediction
def preprocess_new_data(new_data):
    categorical_columns = ['location', 'payment_method', 'transaction_status', 'transaction_type']
    for col in categorical_columns:
        if col in new_data.columns:
            le = label_encoders[col]
            new_data[col] = le.transform(new_data[col])
    X_new = new_data.drop(columns=['transaction_id'])
    return X_new

# Function to send login alert email
def send_login_alert_email(user_email, username):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_FROM
    msg['To'] = user_email
    msg['Subject'] = 'Login Alert'
    body = f'User "{username}" has successfully logged in.'
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_FROM, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_FROM, user_email, text)
        server.quit()
        print('Login alert email sent successfully.')
    except Exception as e:
        print(f"Error sending email: {e}")

# Function to send a fraud alert email
def send_fraud_alert_email(raw_transaction_data, user_email):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_FROM
    msg['To'] = user_email
    msg['Subject'] = 'Fraud Alert Detected'

    # Construct the email body with raw (entered) data
    body = f"""Fraudulent transaction detected:

    Transaction ID: {raw_transaction_data['transaction_id']}
    Amount: {raw_transaction_data['amount']}
    Location: {raw_transaction_data['location']}
    Payment Method: {raw_transaction_data['payment_method']}
    Transaction Status: {raw_transaction_data['transaction_status']}
    Transaction Type: {raw_transaction_data['transaction_type']}
    Frequent Transactions: {raw_transaction_data['frequent_transactions']}
    High Refunds: {raw_transaction_data['high_refunds']}
    """

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_FROM, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_FROM, user_email, text)
        server.quit()
        print('Fraud alert email sent successfully.')
    except Exception as e:
        print(f"Error sending fraud alert email: {e}")


# Routes
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route('/info')
def info():
    return render_template('info.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        transaction_limit = float(request.form['transaction_limit'])
        
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password, email, transaction_limit) VALUES (?, ?, ?, ?)', 
                         (username, password, email, transaction_limit))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Try a different one.', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
                            (username, password)).fetchone()
        conn.close()
        
        if user:
            session['username'] = username
            send_login_alert_email(user['email'], username)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/index', methods=['GET', 'POST'])
def index():
    if 'username' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    # Check if the user's transaction limit is expired
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    conn.close()

    if user:
        last_limit_update = datetime.datetime.strptime(user['last_limit_update'], '%Y-%m-%d')
        if (datetime.datetime.now() - last_limit_update).days > 30:
            conn = get_db_connection()
            conn.execute('UPDATE users SET transaction_limit = 100000, last_limit_update = ? WHERE username = ?',
                         (datetime.datetime.now().strftime('%Y-%m-%d'), session['username']))
            conn.commit()
            conn.close()
            flash(f"Your transaction limit has been reset to 100,000 due to inactivity.", 'info')

    if request.method == 'POST':
        amount = float(request.form['amount'])

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
        conn.close()

        if amount > user['transaction_limit']:
            flash(f"Warning: Amount exceeds your set limit of {user['transaction_limit']}. Please review the transaction.", 'warning')
            return render_template('index.html')

        new_limit = user['transaction_limit'] - amount
        if new_limit < 0:
            flash("Warning: Transaction exceeds the total allowed limit for the next 30 days. Please review your transactions.", 'warning')
            return render_template('index.html')

        conn = get_db_connection()
        conn.execute('UPDATE users SET transaction_limit = ?, last_limit_update = ? WHERE username = ?',
                     (new_limit, datetime.datetime.now().strftime('%Y-%m-%d'), session['username']))
        conn.commit()
        conn.close()

        # Prepare new data for prediction
        new_data = pd.DataFrame({
            'transaction_id': [int(request.form['transaction_id'])],
            'amount': [amount],
            'location': [request.form['location']],
            'payment_method': [request.form['payment_method']],
            'transaction_status': [request.form['transaction_status']],
            'transaction_type': [request.form['transaction_type']],
            'frequent_transactions': [int(request.form['frequent_transactions'])],
            'high_refunds': [int(request.form['high_refunds'])]
        })

        # Preprocess and predict fraud
        X_new = preprocess_new_data(new_data)
        predictions = model.predict(X_new)
        prediction_label = 'Non-Fraud' if predictions[0] == 0 else 'Fraud'

        if prediction_label == 'Fraud':
            raw_transaction_data = {
                'transaction_id': request.form['transaction_id'],
                'amount': request.form['amount'],
                'location': request.form['location'],
                'payment_method': request.form['payment_method'],
                'transaction_status': request.form['transaction_status'],
                'transaction_type': request.form['transaction_type'],
                'frequent_transactions': request.form['frequent_transactions'],
                'high_refunds': request.form['high_refunds']
            }
            send_fraud_alert_email(raw_transaction_data, user['email'])

        conn = get_db_connection()
        conn.execute('''INSERT INTO transactions (transaction_id, amount, location, payment_method, transaction_status,
                                                  transaction_type, frequent_transactions, high_refunds, prediction)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
            int(request.form['transaction_id']),
            amount,
            request.form['location'],
            request.form['payment_method'],
            request.form['transaction_status'],
            request.form['transaction_type'],
            int(request.form['frequent_transactions']),
            int(request.form['high_refunds']),
            prediction_label
        ))
        conn.commit()
        conn.close()

        return render_template('prediction.html', transaction_id=new_data['transaction_id'][0], prediction=prediction_label)

    return render_template('index.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
