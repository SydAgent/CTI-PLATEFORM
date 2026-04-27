"""
ONYX CTI v5.0 SOVEREIGN — Event Bus (Pub/Sub)
==============================================

Implémentation asynchrone hautement performante d'un Bus d'Événements
basé sur Redis Streams. Découple totalement l'ingestion (producteurs)
du traitement et de la persistance (consommateurs).

Garanties :
- Scalabilité horizontale (Groupes de consommateurs)
- Tolérance aux pannes (Retries, XACK)
- O(1) appending
"""

import json
from typing import Any, AsyncGenerator

from structlog import get_logger
from onyx_core.services.redis import RedisService
from redis.asyncio import Redis

logger = get_logger("onyx.event_bus")

class EventBus:
    """Bus d'événements central de la plateforme."""

    def __init__(self, redis_svc: RedisService):
        self.redis: Redis = redis_svc.client

    async def publish(self, stream_name: str, event_type: str, data: dict[str, Any]) -> str:
        """Publie un événement sur le stream spécifié."""
        payload = {
            "event_type": event_type,
            "data": json.dumps(data)
        }
        try:
            # XADD: Ajoute l'événement au stream avec ID auto-généré (*)
            # Maxlen: Limite la taille pour éviter la saturation RAM en production
            msg_id = await self.redis.xadd(stream_name, payload, maxlen=100000, approximate=True)
            logger.debug("event_bus.published", stream=stream_name, msg_id=msg_id.decode())
            return msg_id.decode()
        except Exception as e:
            logger.error("event_bus.publish.error", stream=stream_name, error=str(e))
            raise

    async def consume(self, stream_name: str, group_name: str, consumer_name: str) -> AsyncGenerator[tuple[str, str, dict], None]:
        """
        Consomme les événements en tant que membre d'un groupe de consommateurs.
        Yields (message_id, event_type, data_dict).
        """
        # Création du groupe de consommateurs (s'il n'existe pas déjà)
        try:
            await self.redis.xgroup_create(stream_name, group_name, id="0", mkstream=True)
        except Exception as e:
            if "BUSYGROUP" not in str(e):
                logger.error("event_bus.consume.group_error", error=str(e))

        logger.info("event_bus.consumer_started", stream=stream_name, group=group_name, consumer=consumer_name)

        while True:
            try:
                # XREADGROUP: Bloque jusqu'à réception de nouveaux messages (id=">")
                streams = await self.redis.xreadgroup(
                    group_name, consumer_name, {stream_name: ">"}, count=100, block=2000
                )
                
                for stream, messages in streams:
                    for msg_id, payload in messages:
                        try:
                            # Décodage (les clés/valeurs Redis arrivent en bytes)
                            event_type = payload.get(b"event_type", b"unknown").decode()
                            data_str = payload.get(b"data", b"{}").decode()
                            data_dict = json.loads(data_str)
                            
                            yield msg_id.decode(), event_type, data_dict
                            
                        except Exception as decode_err:
                            logger.error("event_bus.consume.decode_error", msg_id=msg_id, error=str(decode_err))
                            
            except asyncio.CancelledError:
                logger.info("event_bus.consumer_stopped", consumer=consumer_name)
                break
            except Exception as e:
                logger.error("event_bus.consume.loop_error", error=str(e))
                await asyncio.sleep(1.0)

    async def acknowledge(self, stream_name: str, group_name: str, message_id: str):
        """Valide le traitement d'un message (évite la re-livraison)."""
        await self.redis.xack(stream_name, group_name, message_id)
