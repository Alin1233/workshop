import uuid
from datetime import datetime

from sqlalchemy import UUID, BigInteger, Boolean, CheckConstraint, DateTime, Text, UniqueConstraint, false, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

# Noms donnés par PostgreSQL aux contraintes UNIQUE déclarées en ligne dans schema.sql.
ACCOUNT_NUMBER_UNIQUE = "accounts_account_number_key"
OWNER_UNIQUE = "accounts_owner_id_key"


class Account(Base):
    __tablename__ = "accounts"

    __table_args__ = (
        UniqueConstraint("account_number", name=ACCOUNT_NUMBER_UNIQUE),
        UniqueConstraint("owner_id", name=OWNER_UNIQUE),
        CheckConstraint("is_system OR balance_cents >= 0", name="balance_non_negative"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True)
    account_number: Mapped[str] = mapped_column(Text, nullable=False)
    # NULL pour le compte système (trésorerie), qui n'a ni propriétaire ni e-mail.
    owner_id: Mapped[uuid.UUID | None] = mapped_column(UUID, nullable=True)
    owner_name: Mapped[str] = mapped_column(Text, nullable=False)
    owner_email: Mapped[str | None] = mapped_column(Text, nullable=True)
    currency: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'EUR'"))
    balance_cents: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=false())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    # Registre en ajout seul : aucune cascade de suppression vers les virements ni les écritures.
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
    )
