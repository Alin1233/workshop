from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from .base import Base


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"

    __table_args__ = (
        CheckConstraint("amount_cents <> 0", name="ledger_entries_amount_cents_check"),
    )

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    transfer_id = Column(
        UUID(as_uuid=True), ForeignKey("transfers.id"), nullable=False
    )
    account_id = Column(
        UUID(as_uuid=True), ForeignKey("accounts.id"), nullable=False
    )
    amount_cents = Column(BigInteger, nullable=False)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    transfer = relationship("Transfer", back_populates="ledger_entries")
    account = relationship("Account", back_populates="ledger_entries")