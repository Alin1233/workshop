"""Base déclarative des modèles SQLAlchemy du registre.

Les modèles sont le miroir de `schema.sql`, qui reste la seule source de vérité : les tables sont créées par ce script
(au démarrage du service, et par les tests), jamais par SQLAlchemy (aucun `create_all`). Les noms de contraintes
reprennent ceux de PostgreSQL, car le registre s'en sert pour reconnaître une violation d'unicité attendue.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
