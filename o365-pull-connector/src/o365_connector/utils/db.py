from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from o365_connector.config import AppConfig
from o365_connector.models import Base


def create_session_factory(config: AppConfig):
    engine = create_engine(config.database_url, future=True)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return scoped_session(session_factory)


def init_db(config: AppConfig):
    return create_session_factory(config)


@contextmanager
def session_scope(Session) -> Iterator:
    session = Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
