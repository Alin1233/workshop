import uuid
from datetime import datetime

from sqlalchemy import UUID, BigInteger, CheckConstraint, DateTime, ForeignKey, Index, Text, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

# Unicité du couple (émetteur, clé d'idempotence) : sa violation signale un virement rejoué, et seulement elle.
# Les virements système (crédit de bienvenue) ont émetteur et clé à NULL : jamais en conflit (NULL distincts).
IDEMPOTENCY_UNIQUE = "idempotency_unique"


class Transfer(Base):
    __tablename__ = "transfers"

    __table_args__ = (
        CheckConstraint("amount_cents > 0", name="transfers_amount_cents_check"),
        CheckConstraint("status IN ('completed')", name="transfers_status_check"),
        CheckConstraint("from_account_id <> to_account_id", name="distinct_accounts"),
        UniqueConstraint("initiated_by", "idempotency_key", name=IDEMPOTENCY_UNIQUE),
        Index("transfers_from_idx", "from_account_id", text("created_at DESC")),
        Index("transfers_to_idx", "to_account_id", text("created_at DESC")),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True)
    from_account_id: Mapped[uuid.UUID] = mapped_column(UUID, ForeignKey("accounts.id"), nullable=False)
    to_account_id: Mapped[uuid.UUID] = mapped_column(UUID, ForeignKey("accounts.id"), nullable=False)
    amount_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    label: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("''"))
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'completed'"))
    # sub du JWT ; NULL pour les opérations système, comme la clé d'idempotence.
    initiated_by: Mapped[uuid.UUID | None] = mapped_column(UUID, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

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
    # Les écritures sont enregistrées avec leur virement (cascade d'ajout par défaut), jamais supprimées par l'ORM.
    ledger_entries = relationship(
        "LedgerEntry",
        back_populates="transfer",
    )
