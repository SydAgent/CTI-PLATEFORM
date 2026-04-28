import structlog
from neo4j import GraphDatabase, Driver
from typing import Optional
import os

logger = structlog.get_logger(__name__)

class Neo4jService:
    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "onyx_graph_secret_2026")
        self._driver: Optional[Driver] = None

    def connect(self):
        if not self._driver:
            try:
                self._driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
                self._driver.verify_connectivity()
                logger.info("Neo4j connected successfully", uri=self.uri)
            except Exception as e:
                logger.error("Failed to connect to Neo4j", error=str(e))
                self._driver = None

    def close(self):
        if self._driver:
            self._driver.close()
            logger.info("Neo4j connection closed")

    def get_session(self):
        if not self._driver:
            self.connect()
        if self._driver:
            return self._driver.session()
        raise Exception("Neo4j driver is not initialized")

neo4j_service = Neo4jService()
