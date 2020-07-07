import time
import os
from binascii import hexlify

from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey
import sqlalchemy.types as types
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import func
from sqlalchemy import or_, and_, desc
from marshmallow import Schema, fields

from database import Base

class PaymentRequestSchema(Schema):
    date = fields.Float()
    token = fields.String()
    asset = fields.String()
    amount = fields.Integer()
    windcave_session_id = fields.String()
    windcave_status = fields.String()
    windcave_authorised = fields.Boolean()
    windcave_allow_retry = fields.Boolean()
    status = fields.String()
    return_url = fields.String()

class PaymentRequest(Base):
    __tablename__ = 'payment_requests'
    id = Column(Integer, primary_key=True)
    date = Column(Float, nullable=False, unique=False)
    token = Column(String, nullable=False, unique=True)
    asset = Column(String, nullable=False)
    amount = Column(Integer, nullable=False)
    windcave_session_id = Column(String)
    windcave_status = Column(String)
    windcave_authorised = Column(Boolean)
    windcave_allow_retry = Column(Boolean)
    status = Column(String)
    return_url = Column(String)

    def __init__(self, token, asset, amount, windcave_session_id, windcave_status, return_url):
        self.date = time.time()
        self.token = token
        self.asset = asset
        self.amount = amount
        self.windcave_session_id = windcave_session_id
        self.windcave_status = windcave_status
        self.status = 'created'
        self.return_url = return_url

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    def __repr__(self):
        return '<PaymentRequest %r>' % (self.token)

    def to_json(self):
        schema = PaymentRequestSchema()
        return schema.dump(self).data

class PayoutRequestSchema(Schema):
    date = fields.Float()
    token = fields.String()
    asset = fields.String()
    amount = fields.Integer()
    sender = fields.String()
    sender_account = fields.String()
    sender_reference = fields.String()
    sender_code = fields.String()
    receiver = fields.String()
    receiver_account = fields.String()
    receiver_reference = fields.String()
    receiver_code = fields.String()
    receiver_particulars = fields.String()
    email = fields.String()
    email_sent = fields.Boolean()
    processed = fields.Boolean()
    status = fields.String()

class PayoutGroupRequest(Base):
    __tablename__ = 'payout_group_requests'
    payout_group_id = Column(Integer, ForeignKey('payout_groups.id'), primary_key=True)
    payout_request_id = Column(Integer, ForeignKey('payout_requests.id'), primary_key=True)

    def __init__(self, group, request):
        self.payout_group_id = group.id
        self.payout_request_id = request.id

class PayoutRequest(Base):
    __tablename__ = 'payout_requests'
    id = Column(Integer, primary_key=True)
    date = Column(Float, nullable=False, unique=False)
    token = Column(String, nullable=False, unique=True)
    secret = Column(String, nullable=False)
    asset = Column(String, nullable=False)
    amount = Column(Integer, nullable=False)
    sender = Column(String, nullable=False)
    sender_account = Column(String, nullable=False)
    sender_reference = Column(String, nullable=False)
    sender_code = Column(String, nullable=False)
    receiver = Column(String, nullable=False)
    receiver_account = Column(String, nullable=False)
    receiver_reference = Column(String, nullable=False)
    receiver_code = Column(String, nullable=False)
    receiver_particulars = Column(String, nullable=False)
    email = Column(String, nullable=False)
    email_sent = Column(Boolean)
    processed = Column(Boolean)
    status = Column(String)
    groups = relationship('PayoutGroup', secondary='payout_group_requests', back_populates='requests')

    def __init__(self, token, asset, amount, sender, sender_account, sender_reference, sender_code, receiver, receiver_account, receiver_reference, receiver_code, receiver_particulars, email, email_sent):
        self.date = time.time()
        self.token = token
        self.secret = str(hexlify(os.urandom(20)), 'ascii').upper()
        self.asset = asset
        self.amount = amount
        self.sender = sender
        self.sender_account = sender_account
        self.sender_reference = sender_reference
        self.sender_code = sender_code
        self.receiver = receiver
        self.receiver_account = receiver_account
        self.receiver_reference = receiver_reference
        self.receiver_code = receiver_code
        self.receiver_particulars = receiver_particulars
        self.email = email
        self.email_sent = email_sent
        self.processed = False
        self.status = 'created'

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    @classmethod
    def not_processed(cls, session):
        return session.query(cls).filter(cls.processed == False).all()

    def __repr__(self):
        return '<PayoutRequest %r>' % (self.token)

    def to_json(self):
        schema = PayoutRequestSchema()
        return schema.dump(self).data

class PayoutGroup(Base):
    __tablename__ = 'payout_groups'
    id = Column(Integer, primary_key=True)
    token = Column(String, nullable=False, unique=True)
    secret = Column(String, nullable=False, unique=True)
    expired = Column(Boolean, nullable=False)
    requests = relationship('PayoutRequest', secondary='payout_group_requests', back_populates='groups')

    def __init__(self):
        self.token = str(hexlify(os.urandom(8)), 'ascii').upper()
        self.secret = str(hexlify(os.urandom(20)), 'ascii').upper()
        self.expired = False

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    @classmethod
    def expire_all_but(cls, session, group):
        session.query(cls).filter(cls.id != group.id).update({"expired": True})
