from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()
engine = create_engine('sqlite:///application_database', connect_args={'check_same_thread': False}, echo=False)
Session = sessionmaker(bind=engine)
db_session = Session()


class User(Base):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(50), nullable=False)


Base.metadata.create_all(engine)


