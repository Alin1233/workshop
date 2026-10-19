from sqlalchemy import Column, UUID, BigInteger, ForeignKey, String, DateTime, CheckConstraint, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
from .base import Base

class Transfer(Base):
    __tablename__ = 'transfers'

    __table_args__ = (
        CheckConstraint("amount_cents > 0", name="transfers_amount_cents_check"),
        CheckConstraint(
            "status IN ('completed')", name="transfers_status_check"
        ),
        CheckConstraint(
            "from_account_id <> to_account_id", name="distinct_accounts"
        ),
        UniqueConstraint(
            "initiated_by", "idempotency_key", name="idempotency_unique"
        ),
    )
    
    id = Column(UUID, primary_key=True)
    from_account_id = Column(UUID, ForeignKey('accounts.id'), nullable=False)
    to_account_id = Column(UUID, ForeignKey('accounts.id'), nullable=False)
    amount_cents = Column(BigInteger, nullable=False)
    label = Column(String(255), nullable=True)
    status = Column(String(20), nullable=False, default='pending')
    initiated_by = Column(UUID, nullable=False)
    idempotency_key = Column(String(36), nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.now)

    from_account = relationship(
        "Account",
        foreign_keys=[from_account_id],
        back_populates="transfers_sent",
    )
    to_account = relationship(
        "Account",
        foreign_keys=[to_account_id],
        back_populates="transfers_received",
    )
    ledger_entries = relationship(
        "LedgerEntry",
        back_populates="transfer",
        cascade="all, delete-orphan",
    )