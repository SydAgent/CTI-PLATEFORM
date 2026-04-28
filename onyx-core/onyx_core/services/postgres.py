import structlog
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from typing import Generator
import os

logger = structlog.get_logger(__name__)

POSTGRES_URL = os.getenv(
    "POSTGRES_URL", 
    "postgresql://onyx_admin:onyx_pg_secret_2026@localhost:5432/onyx_cti"
)

Base = declarative_base()

class PostgresService:
    def __init__(self):
        self.engine = None
        self.SessionLocal = None

    def connect(self):
        try:
            self.engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            logger.info("PostgreSQL engine created successfully")
        except Exception as e:
            logger.error("Failed to connect to PostgreSQL", error=str(e))

    def get_db(self) -> Generator:
        if not self.SessionLocal:
            self.connect()
        db = self.SessionLocal()
        try:
            yield db
        finally:
            db.close()

postgres_service = PostgresService()
