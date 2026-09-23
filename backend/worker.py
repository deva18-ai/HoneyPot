import signal
import sys
from contextlib import asynccontextmanager

import redis
from rq import Connection, Queue, Worker

from backend.core.config import get_settings
from backend.db.session import close_db, init_db

settings = get_settings()


@asynccontextmanager
async def lifespan():
    await init_db()
    yield
    await close_db()


def run_worker():
    redis_conn = redis.from_url(settings.REDIS_URL)

    with Connection(redis_conn):
        worker = Worker(
            queues=[
                Queue("default"),
                Queue("detection"),
                Queue("enrichment"),
                Queue("reports"),
            ],
            connection=redis_conn,
        )

        def shutdown(signum, frame):
            print("Shutting down worker...")
            sys.exit(0)

        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)

        worker.work(with_scheduler=True)


if __name__ == "__main__":
    run_worker()
