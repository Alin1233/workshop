from sqlalchemy import Column, String, UUID, BigInteger, Boolean, DateTime, CheckConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
from .base import Base

class Account(Base) :
    __tablename__ = 'accounts'

    __table_args__ = (
        CheckConstraint(
            "is_system OR balance_cents >= 0", name="balance_non_negative"
        ),
    )
    
    id = Column(UUID, primary_key=True)
    account_number = Column(String(20), unique=True, nullable=False)
    owner_id = Column(UUID, unique=True, nullable=False)
    owner_name = Column(String(100), nullable=False)
    owner_email = Column(String(100), unique=True, nullable=False)
    currency = Column(String(3), nullable=False, default='EUR')
    balance_cents = Column(BigInteger, nullable=False, default=0)
    is_system = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.now)

    transfers_sent = relationship(
        "Transfer",
        foreign_keys="Transfer.from_account_id",
        back_populates="from_account",
    )
    transfers_received = relationship(
        "Transfer",
        foreign_keys="Transfer.to_account_id",
        back_populates="to_account",
    )
    ledger_entries = relationship(
        "LedgerEntry",
        back_populates="account",
        cascade="all, delete-orphan",
    )