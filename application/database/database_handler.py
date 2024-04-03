from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

Base = declarative_base()
engine = create_engine('sqlite:///database/application_database.db', connect_args={'check_same_thread': False}, echo=False)
Session = sessionmaker(bind=engine)
db_session = Session()

class User(Base):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(50), nullable=False)
    # Establish a relationship to the Group entity
    groups = relationship('Group', back_populates='user')

class Group(Base):
    __tablename__ = 'groups'
    group_id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(String(250))
    user_id = Column(Integer, ForeignKey('users.user_id'))
    # Establish relationships
    user = relationship('User', back_populates='groups')
    passwords = relationship('Password', back_populates='group')

class Password(Base):
    __tablename__ = 'passwords'
    password_id = Column(Integer, primary_key=True)
    site_name = Column(String(100), nullable=False)
    site_url = Column(String(255))
    username = Column(String(50), nullable=False)
    password = Column(String(50), nullable=False)
    group_id = Column(Integer, ForeignKey('groups.group_id'))
    # Establish a relationship to the Group entity
    group = relationship('Group', back_populates='passwords')

# Create all tables in the engine. This is equivalent to "Create Table"
# statements in raw SQL.
Base.metadata.create_all(engine)



