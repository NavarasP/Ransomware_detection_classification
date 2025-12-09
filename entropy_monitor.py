import os
import sys
import time
import json
import math
import random
import argparse
import threading
from pathlib import Path
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ---------- parameters ----------
SAMPLE_BLOCK = 4096
NUM_RANDOM_BLOCKS = 3
MAX_TOTAL_SAMPLE = 64 * 1024
ENTROPY_THRESHOLD = 7.2         # absolute entropy threshold
ENTROPY_DELTA_THRESHOLD = 0.9  # increase vs baseline
DEBOUNCE_SECONDS = 0.5         # coalesce repeated events
BASELINE_FILE = "entropy_baseline.json"
EXCLUDE_EXT = {'.zip', '.rar', '.7z', '.gz', '.jpg', '.jpeg', '.png', '.mp4', '.mp3', '.iso'}
EXCLUDE_DIRS = []  # add system dirs here (absolute paths)
# -------------------------------

lock = threading.Lock()
last_event_time = defaultdict(float)

def shannon_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for f in freq:
        if f:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy

def sample_entropy_of_file(path: Path) -> float:
    try:
        size = path.stat().st_size
        if size == 0:
            return 0.0
        to_read = min(MAX_TOTAL_SAMPLE, size)
        chunks = []
        # always read first block
        with path.open('rb') as fh:
            fh.seek(0)
            chunks.append(fh.read(min(SAMPLE_BLOCK, to_read)))
            read_total = len(chunks[-1])
            # add random blocks
            for _ in range(NUM_RANDOM_BLOCKS):
                if read_total >= to_read:
                    break
                start = random.randint(0, max(0, size - SAMPLE_BLOCK))
                fh.seek(start)
                chunk = fh.read(min(SAMPLE_BLOCK, to_read - read_total))
                if not chunk:
                    break
                chunks.append(chunk)
                read_total += len(chunk)
        data = b''.join(chunks)
        return shannon_entropy_bytes(data)
    except Exception as e:
        # file might be locked; return 0 so it won't trigger
        return 0.0

class EntropyHandler(FileSystemEventHandler):
    def __init__(self, baseline):
        super().__init__()
        self.baseline = baseline

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle_event(event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle_event(event.src_path)

    def on_moved(self, event):
        # treat destination as created
        if event.is_directory:
            return
        self._handle_event(event.dest_path)

    def _handle_event(self, src_path):
        path = Path(src_path)
        ext = path.suffix.lower()
        abs_path = str(path.resolve())
        # basic excludes
        if ext in EXCLUDE_EXT:
            return
        for d in EXCLUDE_DIRS:
            if abs_path.startswith(d):
                return
        now = time.time()
        with lock:
            if now - last_event_time[abs_path] < DEBOUNCE_SECONDS:
                return
            last_event_time[abs_path] = now
        # run sampling in a worker thread
        t = threading.Thread(target=process_file, args=(path, self.baseline), daemon=True)
        t.start()

def process_file(path: Path, baseline):
    # small sleep to allow writer to finish briefly
    time.sleep(0.2)
    if not path.exists():
        return
    # skip if too big to sample? sampling handles sizes
    ent = sample_entropy_of_file(path)
    key = str(path.resolve())
    prev = baseline.get(key)
    baseline[key] = ent
    # check thresholds
    delta = None if prev is None else (ent - prev)
    suspicious = False
    reasons = []
    if ent >= ENTROPY_THRESHOLD:
        suspicious = True
        reasons.append(f"entropy {ent:.2f} >= {ENTROPY_THRESHOLD}")
    if prev is not None and delta is not None and delta >= ENTROPY_DELTA_THRESHOLD:
        suspicious = True
        reasons.append(f"entropy increased by {delta:.2f} (>= {ENTROPY_DELTA_THRESHOLD})")
    if suspicious:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(f"[ALERT {ts}] {path} | ent={ent:.2f} prev={prev} delta={delta if delta is not None else 'N/A'} reasons={';'.join(reasons)}")

def load_baseline(path):
    if os.path.exists(path):
        try:
            with open(path, 'r') as fh:
                return json.load(fh)
        except Exception:
            return {}
    return {}

def save_baseline(path, baseline):
    try:
        with open(path + ".tmp", 'w') as fh:
            json.dump(baseline, fh)
        os.replace(path + ".tmp", path)
    except Exception:
        pass

def main(watch_paths):
    baseline = load_baseline(BASELINE_FILE)
    event_handler = EntropyHandler(baseline)
    obs = Observer()
    for p in watch_paths:
        obs.schedule(event_handler, p, recursive=True)
    obs.start()
    print("Monitoring paths:", watch_paths)
    try:
        while True:
            time.sleep(5)
            # periodically persist baseline
            with lock:
                save_baseline(BASELINE_FILE, baseline)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Entropy-based file change monitor")
    parser.add_argument("paths", nargs="+", help="Paths to monitor (absolute)")
    args = parser.parse_args()
    # add common excludes for Windows and Linux if not provided
    if sys.platform.startswith("win"):
        EXCLUDE_DIRS.extend([str(Path("C:/Windows").resolve()), str(Path("C:/Program Files").resolve()), str(Path("C:/Program Files (x86)").resolve())])
    else:
        EXCLUDE_DIRS.extend([str(Path("/proc").resolve()), str(Path("/sys").resolve()), str(Path("/dev").resolve())])
    main(args.paths)
