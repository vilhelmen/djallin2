#!/usr/bin/env python3

import sqlite3
import threading

from pathlib import Path
import logging
import queue
import traceback

logger = logging.getLogger(__name__)


class StatTracker():
    def __init__(self, database: Path):
        self._shutdown = threading.Event()
        self._queue = queue.Queue()

        self._writer = threading.Thread(target=self._writer_func, name='stat_writer', args=(database,))
        self._writer.start()

    def _writer_func(self, db_path):
        db = sqlite3.connect(str(db_path))
        with db:
            db.execute('CREATE TABLE IF NOT EXISTS stats (source text, sender text, func_name text, timestamp real, message text);')
        while not self._shutdown.is_set():
            self._shutdown.wait(300)  # flush every 5 minutes
            if not self._queue.empty():
                logger.info('Saving stats')
                entry = None
                try:
                    with db:
                        while not self._queue.empty():
                            entry = self._queue.get()
                            db.execute('INSERT INTO stats VALUES (?, ?, ?, ?, ?)', entry)
                except Exception as err:
                    logger.error(f'{err} during stat database flush for entry {entry}')
                    logger.error(traceback.format_exc())
        db.close()

    def submit(self, source: str, sender: str, func_name: str, timestamp: int, message: str):
        # Hope that blocking record doesn't come back to bite me
        self._queue.put((source, sender, func_name, timestamp, message))

    def __del__(self):
        self._shutdown.set()
        self._writer.join()
