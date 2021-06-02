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
        build = not database.is_file()

        self._db = sqlite3.connect(str(database))
        self._writer = None
        self._shutdown = threading.Event()
        self._queue = queue.Queue()

        if build:
            logging.info('Database does not exist, creating.')
            with self._db:
                self._db.execute('CREATE TABLE stats (where text, who text, what text, when real, message text)')

    def _writer_func(self):
        while not self._shutdown.is_set():
            self._shutdown.wait(300)  # flush every 5 minutes
            if not self._queue.empty():
                entry = None
                try:
                    with self._db:
                        while not self._queue.empty():
                            entry = self._queue.get()
                            self._db.execute('INSERT INTO TABLE stats VALUES (?, ?, ?, ?, ?)', entry)
                except Exception as err:
                    logger.error(f'{err} during stat database flush for entry {entry}')
                    logger.error(traceback.format_exc())

    def submit(self, type: str, who: str, what: str, when: int, message: str):
        # Hope that blocking record doesn't come back to bite me
        self._queue.put((type, who, what, when, message))

    def __del__(self):
        self._shutdown.set()
        self._writer.join()
        self._db.close()
