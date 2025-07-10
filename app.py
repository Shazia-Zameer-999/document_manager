# --------- Import Required Modules ----------
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, flash
import os
from werkzeug.utils import secure_filename

# --------- App Initialization ----------
app = Flask(__name__)

app.secret_key = 'shazia_secret_key_2025'  # Needed to use sessions

# --------- Configurations ----------
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Dummy admin credentials (you can change later)
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'pass123'

# If uploads folder doesn't exist, create it
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --------- Login Page ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user'] = username
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Try again.')

    return render_template('login.html')

# --------- Register Page ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect('users.db',timeout=5)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                           (username, hashed_password, email))
            conn.commit()
            conn.close()
            flash('Registered successfully! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Try a different one.')

    return render_template('register.html')

# --------- Home Page Route ----------
@app.route('/')
def index():
    return render_template('index.html')  # Shows home page

# --------- Upload Page Route ----------
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        category = request.form['category']
        username = session['user']

        if file and category:
            filename = file.filename
            category_folder = os.path.join(app.config['UPLOAD_FOLDER'], category)

            if not os.path.exists(category_folder):
                os.makedirs(category_folder)

            file.save(os.path.join(category_folder, filename))

            # Save upload info to DB
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO files (username, filename, category) VALUES (?, ?, ?)",
                           (username, filename, category))
            conn.commit()
            conn.close()

            flash('File uploaded successfully!')
            return redirect(url_for('view_files'))

    return render_template('upload.html')

# --------- View Uploaded Categories ----------
@app.route('/files')
def view_files():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT category, COUNT(*) FROM files WHERE username = ? GROUP BY category", (username,))
    categories = cursor.fetchall()
    conn.close()

    return render_template('view_files.html', categories=categories)

# --------- View Files in a Category ----------
@app.route('/files/<category>')
def view_category_files(category):
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT filename FROM files WHERE username = ? AND category = ?", (username, category))
    files = [row[0] for row in cursor.fetchall()]
    conn.close()

    return render_template('view_files.html', files=files, category=category)

# --------- Search Files Route ----------
@app.route('/search', methods=['GET'])
def search_files():
    if 'user' not in session:
        return redirect(url_for('login'))

    query = request.args.get('q', '').strip().lower()
    username = session['user']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Fetch files where filename or category matches the query
    cursor.execute("""
        SELECT filename, category FROM files 
        WHERE username = ? AND 
        (LOWER(filename) LIKE ? OR LOWER(category) LIKE ?)
    """, (username, f'%{query}%', f'%{query}%'))

    results = cursor.fetchall()
    conn.close()

    return render_template('view_files.html', search_results=results, search_query=query)
# --------- Delete File Route ----------
@app.route('/delete/<category>/<filename>', methods=['POST'])
def delete_file(category, filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], category, filename)

    # Delete from file system
    if os.path.exists(file_path):
        os.remove(file_path)

    # Delete from database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM files WHERE username = ? AND filename = ? AND category = ?",
                   (username, filename, category))
    conn.commit()
    conn.close()

    flash('File deleted successfully.')
    return redirect(url_for('view_category_files', category=category))

# --------- Download File Route ----------
@app.route('/download/<category>/<filename>')
def download_file(category, filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], category)
    return send_from_directory(folder_path, filename, as_attachment=True)


# --------- Preview File Route ----------
@app.route('/preview/<category>/<filename>')
def preview_file(category, filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], category, filename)
    ext = filename.lower().split('.')[-1]

    # Return HTML page that previews file
    return render_template('preview.html', category=category, filename=filename, file_type=ext)

# --------- Serve Uploaded Files ----------
@app.route('/uploads/<category>/<filename>')
def uploaded_file(category, filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], category), filename)

# --------- Rename File Route ----------
@app.route('/rename/<category>/<old_filename>', methods=['POST'])
def rename_file(category, old_filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    new_filename = request.form['new_filename'].strip()
    if not new_filename:
        flash("New filename cannot be empty.")
        return redirect(url_for('view_category_files', category=category))

    username = session['user']

    old_path = os.path.join(app.config['UPLOAD_FOLDER'], category, old_filename)
    new_path = os.path.join(app.config['UPLOAD_FOLDER'], category, new_filename)

    if os.path.exists(new_path):
        flash("A file with this name already exists.")
        return redirect(url_for('view_category_files', category=category))

    # Rename the file on disk
    os.rename(old_path, new_path)

    # Update filename in DB
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE files 
        SET filename = ? 
        WHERE username = ? AND filename = ? AND category = ?
    """, (new_filename, username, old_filename, category))
    conn.commit()
    conn.close()

    flash("File renamed successfully!")
    return redirect(url_for('view_category_files', category=category))
# --------- Logout Route ----------
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully.')
    return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    username = request.args.get('username', '')

    email = ''
    if username:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            email = result[0] if result and result[0] else ''
            if not email:
                flash("❗ No email was registered for this user.")
                return redirect(url_for('login'))
        else:
            flash('⚠️ Username not found. Please try again.')
            return redirect(url_for('login'))

    if request.method == 'POST':
        submitted_email = request.form['email']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE email = ?", (submitted_email,))
        user = cursor.fetchone()

        if user:
            import secrets
            token = secrets.token_urlsafe(16)
            cursor.execute("UPDATE users SET reset_token = ? WHERE email = ?", (token, submitted_email))
            conn.commit()
            conn.close()

            reset_link = f"https://turkey-excited-maggot.ngrok-free.app/reset/{token}"
            from utils.email_sender import send_reset_email
            try:
                send_reset_email(submitted_email, reset_link)
                flash('✅ Reset link sent to your email.')
            except Exception as e:
                print("Email error:", e)
                flash('❌ Failed to send email. Please check your sender credentials.')
        else:
            flash('⚠️ Email not found.')

    return render_template('reset_request.html', email=email)
# --------- Reset Password Route ----------

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form['password']
        hashed = generate_password_hash(new_password)

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ?, reset_token = NULL WHERE reset_token = ?", (hashed, token))
        conn.commit()
        conn.close()

        flash('Password has been reset. Please login.')
        return redirect(url_for('login'))

    return render_template('reset_password.html')




# --------- Import Required Modules ----------
import secrets
from flask import request, render_template, flash, redirect, url_for
from utils.email_sender import send_reset_email

# Generate a random token
def generate_token():
    return secrets.token_urlsafe(16)

@app.route('/reset-request', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        token = generate_token()

        # Save token to database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET reset_token = ? WHERE email = ?", (token, email))
        conn.commit()
        conn.close()

        # 💡 Use your ngrok link here:~
        reset_link = f"https://13df-2401-4900-88d3-6e3c-21fd-f9cb-d3e0-a0c6.ngrok-free.app/reset/{token}"

        # Send email
        send_reset_email(email, reset_link)

        flash("Password reset link has been sent to your email.")
        return redirect(url_for('login'))

    return render_template('reset_request.html')


# --------- Profile Page Route ----------

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    # Check if this is a POST to update profile
    if request.method == 'POST':
        new_username = request.form['username']
        new_email = request.form['email']
        new_password = request.form['password']

        update_query = "UPDATE users SET username = ?, email = ?"
        params = [new_username, new_email]

        if new_password:
            hashed_password = generate_password_hash(new_password)
            update_query += ", password = ?"
            params.append(hashed_password)

        update_query += " WHERE username = ?"
        params.append(username)

        cursor.execute(update_query, tuple(params))
        conn.commit()
        conn.close()

        session['user'] = new_username
        flash("✅ Profile updated successfully.")
        return redirect(url_for('profile'))

    # Check if 'edit' mode is triggered via query string
    is_editing = request.args.get('edit') == 'true'
    conn.close()
    return render_template('profile.html', user=user, editing=is_editing)

# --------- Run the App ----------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)