import uuid
from datetime import datetime

from sqlalchemy import UUID, BigInteger, CheckConstraint, DateTime, ForeignKey, Index, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"

    __table_args__ = (
        CheckConstraint("amount_cents <> 0", name="ledger_entries_amount_cents_check"),
        Index("ledger_entries_account_idx", "account_id"),
        Index("ledger_entries_transfer_idx", "transfer_id"),
    )

    # BIGSERIAL : numéro attribué par la séquence de PostgreSQL, relu par RETURNING.
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    transfer_id: Mapped[uuid.UUID] = mapped_column(UUID, ForeignKey("transfers.id"), nullable=False)
    account_id: Mapped[uuid.UUID] = mapped_column(UUID, ForeignKey("accounts.id"), nullable=False)
    amount_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    transfer = relationship("Transfer", back_populates="ledger_entries")
    account = relationship("Account", back_populates="ledger_entries")
