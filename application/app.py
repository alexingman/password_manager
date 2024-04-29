from flask import Flask, render_template, request, redirect, url_for, flash, session as flask_session, jsonify
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import generate_csrf
from flask_wtf import CSRFProtect
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.database_handler import Base, User, Group, Password
from database.password_encrypting import encrypt_password, decrypt_password, decrypt_passwords
import secrets
import string

app = Flask(__name__, static_folder='static', template_folder='templates')
secret_key = secrets.token_hex(64)
app.secret_key = secret_key
app.config['SECRET_KEY'] = secret_key
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# Specify the correct path to the database file
database_path = 'sqlite:///database/application_database.db'
engine = create_engine(database_path, connect_args={'check_same_thread': False}, echo=False)
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
db_session = DBSession()


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = db_session.query(User).filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        flask_session['user_id'] = user.user_id
        return redirect(url_for('dashboard'))
    else:
        flash("Invalid username or password")
        return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username is already taken
        existing_user = db_session.query(User).filter_by(username=username).first()
        if existing_user:
            flash("Username already exists!")
            return redirect(url_for('register'))

        # Check if password is at least 8 characters long
        if len(password) < 8:
            flash("Password must be at least 8 characters long!")
            return redirect(url_for('register'))

        # Hash the password and username before storing it in the database
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create a new user and add it to the database
        new_user = User(username=username, password=hashed_password)
        db_session.add(new_user)
        db_session.commit()

        flash("Registration successful! Please log in.")
        return redirect(url_for('index'))
    else:
        return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in flask_session:
        flash("Please log in to view your dashboard.")
        return redirect(url_for('login'))

    user_id = flask_session['user_id']
    user_groups = db_session.query(Group).filter_by(user_id=user_id).all()
    return render_template('dashboard.html', user_groups=user_groups)


@app.route('/view_group/<int:group_id>')
def view_group(group_id):
    if 'user_id' not in flask_session:
        return redirect(url_for('index'))

    group = db_session.query(Group).filter_by(group_id=group_id, user_id=flask_session['user_id']).first()
    if not group:
        flash("Group not found or you don't have permission to view it.")
        return redirect(url_for('index'))

    passwords = db_session.query(Password).filter_by(group_id=group.group_id).all()
    decrypted_passwords = decrypt_passwords(passwords)

    return render_template('view_group.html', group=group, passwords=decrypted_passwords)



@app.route('/create_group', methods=['GET', 'POST'])
def create_group():
    if 'user_id' not in flask_session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        group_name = request.form['group_name']
        group_description = request.form.get('group_description', '')

        new_group = Group(name=group_name, description=group_description, user_id=flask_session['user_id'])
        db_session.add(new_group)
        db_session.commit()

        flash('New password group created successfully.')
        return redirect(url_for('dashboard'))

    return render_template('create_group.html')

@app.route('/logout')
def logout():
    flask_session.clear()
    return redirect(url_for('index'))


@app.route('/add_password/<int:group_id>', methods=['GET', 'POST'])
def add_password(group_id):
    if 'user_id' not in flask_session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        site_name = request.form['site_name']
        site_url = request.form.get('site_url', '')
        username = request.form['username']
        raw_password = request.form['password']
        encrypted_password = encrypt_password(raw_password)
        new_password = Password(site_name=site_name, site_url=site_url, username=username, password=encrypted_password,
                                group_id=group_id)
        db_session.add(new_password)
        db_session.commit()

        return redirect(url_for('view_group', group_id=group_id))

    return render_template('add_password.html', group_id=group_id)

@app.route('/generate_password')
def generate_password():
    length = 12
    characters = string.ascii_letters + string.digits + string.punctuation
    secure_password = ''.join(secrets.choice(characters) for i in range(length))
    return jsonify(password=secure_password)


@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
def edit_password(password_id):
    if 'user_id' not in flask_session:
        return redirect(url_for('login'))

    password = db_session.query(Password).filter_by(password_id=password_id).first()
    if not password:
        flash('Password not found.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        password.site_name = request.form['site_name']
        password.site_url = request.form.get('site_url', '')
        password.username = request.form['username']
        password.password = encrypt_password(request.form['password'])  # Re-encrypt the new or edited password
        db_session.commit()
        flash('Password updated successfully.')
        return redirect(url_for('view_group', group_id=password.group_id))
    else:
        decrypted_password = decrypt_password(password.password)  # Decrypt the password for display
        return render_template('edit_password.html', password=password, decrypted_password=decrypted_password)




@app.route('/delete_password/<int:password_id>')
def delete_password(password_id):
    if 'user_id' not in flask_session:
        return redirect(url_for('login'))

    password = db_session.query(Password).filter_by(password_id=password_id).first()
    if password:
        db_session.delete(password)
        db_session.commit()
        flash('Password deleted successfully.')
    else:
        flash('Password not found.')

    return redirect(url_for('view_group', group_id=password.group_id))


@app.route('/delete_group/<int:group_id>', methods=['POST'])
def delete_group(group_id):
    if 'user_id' not in flask_session:
        return redirect(url_for('login'))

    group = db_session.query(Group).filter_by(group_id=group_id).first()
    if not group:
        flash("Group not found.", "error")
        return redirect(url_for('dashboard'))

    if group.passwords:
        flash("Cannot delete a group that contains passwords.", "error")
        return redirect(url_for('dashboard'))

    db_session.delete(group)
    db_session.commit()
    flash("Group deleted successfully.", "success")
    return redirect(url_for('dashboard'))


@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in flask_session:
        flash("You need to be logged in to delete your account.")
        return redirect(url_for('login'))

    user_id = flask_session['user_id']
    user = db_session.query(User).filter_by(user_id=user_id).first()

    if user:
        if user.groups:
            flash("Cannot delete account that contains password groups", "error")
            return redirect(url_for('dashboard'))
        db_session.delete(user)
        db_session.commit()
        flask_session.pop('user_id', None)  # Clear user session
        flash("Your account has been successfully deleted.")
        return redirect(url_for('index'))
    else:
        flash("User not found.")
        return redirect(url_for('dashboard'))


@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf())



if __name__ == '__main__':
    app.run(debug=True)






