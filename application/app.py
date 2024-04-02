from flask import Flask, render_template, request, redirect, url_for, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.users import Base, User
import secrets

app = Flask(__name__, static_folder='static', template_folder='templates')
secret_key = secrets.token_hex(32)
app.secret_key = secret_key

# Specify the correct path to the database file
database_path = 'sqlite:///database/application_database.db'
engine = create_engine(database_path, connect_args={'check_same_thread': False}, echo=False)
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = session.query(User).filter_by(username=username, password=password).first()
    if user:
        return redirect(url_for('success'))
    else:
        flash("Invalid username or password")
        return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username is already taken
        existing_user = session.query(User).filter_by(username=username).first()
        if existing_user:
            flash("Username already exists!")
            return redirect(url_for('register'))

        # Check if password is at least 8 characters long
        if len(password) < 8:
            flash("Password must be at least 8 characters long!")
            return redirect(url_for('register'))

        # Create a new user and add it to the database
        new_user = User(username=username, password=password)
        session.add(new_user)
        session.commit()

        flash("Registration successful! Please log in.")
        return redirect(url_for('index'))
    else:
        return render_template('register.html')


@app.route('/success')
def success():
    return "Operation successful!"


if __name__ == '__main__':
    app.run(debug=True)






