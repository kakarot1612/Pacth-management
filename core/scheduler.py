import time
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from core.config import logger

class AutoScanScheduler:
    """
    Automated background scheduler for continuous vulnerability scans:
    - Periodically queries Wazuh API for all managed agents.
    - Updates local vulnerability inventory & compliance metrics.
    - Tracks last scan and next scheduled scan times.
    """

    def __init__(self, interval_minutes: int = 15):
        import os
        env_interval = os.environ.get("AUTO_SCAN_INTERVAL_MINUTES")
        if env_interval:
            try:
                interval_minutes = int(env_interval)
            except Exception:
                pass
        self.interval_seconds = max(3 * 60, interval_minutes * 60)
        self.is_running = False
        self.is_scanning = False
        self.last_scan_time: Optional[datetime] = None
        self.next_scan_time: Optional[datetime] = None
        self.scan_count = 0
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self._stop_event.clear()
        self.next_scan_time = datetime.now() + timedelta(seconds=self.interval_seconds)
        self._thread = threading.Thread(target=self._run_loop, name="WazuhAutoScanWorker", daemon=True)
        self._thread.start()
        logger.info(f"AutoScanScheduler started. Interval: {self.interval_seconds // 60} minutes.")

    def stop(self):
        self.is_running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        logger.info("AutoScanScheduler stopped.")

    def trigger_immediate_scan(self):
        """Spawns an asynchronous one-off scan if not currently scanning"""
        if self.is_scanning:
            return False
        threading.Thread(target=self._execute_scan, name="ManualScanWorker", daemon=True).start()
        return True

    def _execute_scan(self):
        if self.is_scanning:
            return
        self.is_scanning = True
        try:
            logger.info("AutoScanScheduler: Starting scheduled vulnerability audit...")
            from main import run_scan
            run_scan(mock=False)
            self.last_scan_time = datetime.now()
            self.scan_count += 1
            self.next_scan_time = self.last_scan_time + timedelta(seconds=self.interval_seconds)
            logger.info(f"AutoScanScheduler: Scan #{self.scan_count} completed successfully at {self.last_scan_time.strftime('%H:%M:%S')}.")
        except Exception as e:
            logger.error(f"AutoScanScheduler scan error: {e}")
        finally:
            self.is_scanning = False

    def _run_loop(self):
        # Initial scan after 30 seconds of server startup if not yet scanned
        self._stop_event.wait(30)
        if not self._stop_event.is_set() and self.last_scan_time is None:
            self._execute_scan()

        while not self._stop_event.is_set():
            now = datetime.now()
            if self.next_scan_time and now >= self.next_scan_time:
                self._execute_scan()
            self._stop_event.wait(15) # Check every 15s

    def get_status(self) -> Dict[str, Any]:
        now = datetime.now()
        remaining_seconds = max(0, int((self.next_scan_time - now).total_seconds())) if self.next_scan_time else 0
        return {
            "is_running": self.is_running,
            "is_scanning": self.is_scanning,
            "interval_minutes": self.interval_seconds // 60,
            "scan_count": self.scan_count,
            "last_scan": self.last_scan_time.strftime("%Y-%m-%d %H:%M:%S") if self.last_scan_time else "Chưa quét",
            "next_scan": self.next_scan_time.strftime("%Y-%m-%d %H:%M:%S") if self.next_scan_time else "Chưa lập lịch",
            "remaining_minutes": round(remaining_seconds / 60, 1)
        }

# Global singleton scheduler
scheduler = AutoScanScheduler(interval_minutes=30)
