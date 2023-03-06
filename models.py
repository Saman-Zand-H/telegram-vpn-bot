from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import (
    ForeignKey,
    Column,
    Integer,
    Date,
    Numeric,
    String,
    Text,
    BigInteger,
    Boolean,
)
from sqlalchemy.dialects.mysql import BIGINT as MYSQLBIGINT
from sqlalchemy.orm import relationship
from datetime import date
import enum


Base = declarative_base()


###### SQLITE3 ######
class V2RayProtocolEnum(enum.Enum):
    vmess = "vmess"
    vless = "vless"


class Offers(Base):
    __tablename__ = "offers"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    users = relationship("Users", secondary="users_offers_link")


class Guests(Base):
    __tablename__ = "guests"
    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False, unique=True, index=True)
    started_at = Column(Date, nullable=False, default=date.today)
    updated_at = Column(Date, nullable=False, default=date.today)


class Users(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    username = Column(String, nullable=False, unique=True, index=True)
    login_code = Column(String, nullable=False, unique=True, index=True)
    started_at = Column(Date, default=date.today, nullable=False)
    updated_at = Column(Date, default=date.today, nullable=False)
    quota = Column(Numeric, nullable=False, default=-1)
    is_authenticated = Column(Boolean, default=False, nullable=False)
    description = Column(Text, nullable=True)
    offers = relationship("Offers", secondary="users_offers_link")


class UsersOffersLink(Base):
    __tablename__ = "users_offers_link"
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    offer_id = Column(Integer, ForeignKey("offers.id"), primary_key=True)


###### MYSQL ######
MySqlBase = declarative_base()
class TrojanUsers(MySqlBase):
    __tablename__ = "users"
    id = Column(BigInteger, primary_key=True)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False, unique=True, index=True)
    quota = Column(BigInteger, nullable=False, default=0)
    download = Column(MYSQLBIGINT(unsigned=True), nullable=False, default=0)
    upload = Column(MYSQLBIGINT(unsigned=True), nullable=False, default=0)
    description = Column(Text, nullable=True, default="")
    

class SSHUsers(MySqlBase):
    __tablename__ = "ssh_users"
    id = Column(BigInteger, primary_key=True)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)
    started_at = Column(Date, default=date.today, nullable=False)
    ends_at = Column(Date, nullable=False)
