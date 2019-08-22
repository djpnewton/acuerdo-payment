import time

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
        self.status = "created"
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
