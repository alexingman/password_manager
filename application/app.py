from flask import Flask, render_template, request, redirect, url_for
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.users import Base, User

app = Flask(__name__)

engine = create_engine('sqlite:///application_database.db', connect_args={'check_same_thread': False}, echo=False)
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = session.query(User).filter_by(username=username, password=password).first()
    if user:
        return redirect(url_for('success'))
    else:
        return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    # Check if the username is already taken
    existing_user = session.query(User).filter_by(username=username).first()
    if existing_user:
        return "Username already exists!"

    # Create a new user and add it to the database
    new_user = User(username=username, password=password)
    session.add(new_user)
    session.commit()

    return redirect(url_for('success'))

@app.route('/success')
def success():
    return "Operation successful!"

if __name__ == '__main__':
    app.run(debug=True)






