import os
import sys
import time
import json
import math
import random
import threading
from pathlib import Path
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Optional, Callable

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
observer_instance: Optional[Observer] = None
baseline: dict = {}
alert_callback: Optional[Callable] = None

def shannon_entropy_bytes(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
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
    """Calculate entropy by sampling first block and random blocks."""
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

def load_baseline(path: str) -> dict:
    """Load baseline entropy data from JSON file."""
    if os.path.exists(path):
        try:
            with open(path, 'r') as fh:
                return json.load(fh)
        except Exception:
            return {}
    return {}


def save_baseline(path: str, data: dict) -> None:
    """Save baseline entropy data to JSON file (atomic write)."""
    try:
        with open(path + ".tmp", 'w') as fh:
            json.dump(data, fh, indent=2)
        os.replace(path + ".tmp", path)
    except Exception:
        pass


def process_file(file_path: str) -> None:
    """
    Process a file, calculate entropy, check thresholds, and update baseline.
    Uses global baseline dict and alert_callback.
    """
    global baseline, alert_callback
    
    try:
        p = Path(file_path)
        
        # Skip excluded extensions
        if p.suffix.lower() in EXCLUDE_EXT:
            return
        
        # Skip excluded directories
        abs_path = str(p.resolve())
        for d in EXCLUDE_DIRS:
            if abs_path.startswith(d):
                return
        
        # Check debounce
        now = time.time()
        with lock:
            if now - last_event_time[abs_path] < DEBOUNCE_SECONDS:
                return
            last_event_time[abs_path] = now
        
        # Wait for file to be fully written
        time.sleep(0.1)
        
        if not p.is_file():
            return
        
        # Calculate entropy
        entropy = sample_entropy_of_file(p)
        prev_entropy = baseline.get(abs_path, None)
        
        # Check thresholds
        is_alert = entropy >= ENTROPY_THRESHOLD
        if prev_entropy is not None:
            delta = entropy - prev_entropy
            if delta >= ENTROPY_DELTA_THRESHOLD:
                is_alert = True
        
        # Update baseline in memory and JSON file
        with lock:
            baseline[abs_path] = entropy
            save_baseline(BASELINE_FILE, baseline)
        
        # Send alert if suspicious
        if is_alert:
            reasons = []
            if entropy >= ENTROPY_THRESHOLD:
                reasons.append(f"ent>={ENTROPY_THRESHOLD}")
            if prev_entropy is not None:
                delta = entropy - prev_entropy
                if delta >= ENTROPY_DELTA_THRESHOLD:
                    reasons.append(f"delta>={ENTROPY_DELTA_THRESHOLD}")
            
            alert_msg = f"[ALERT {time.strftime('%H:%M:%S')}] {abs_path} | ent={entropy:.2f} prev={prev_entropy:.2f if prev_entropy else 'N/A'} reasons={','.join(reasons)}"
            
            if alert_callback:
                alert_callback(alert_msg)
            else:
                print(alert_msg)
    
    except Exception as e:
        error_msg = f"[ERROR] {file_path}: {str(e)}"
        if alert_callback:
            alert_callback(error_msg)


class EntropyHandler(FileSystemEventHandler):
    """Watchdog event handler for entropy monitoring."""
    
    def on_created(self, event):
        if not event.is_directory:
            # Process file in background thread
            t = threading.Thread(target=process_file, args=(event.src_path,), daemon=True)
            t.start()
    
    def on_modified(self, event):
        if not event.is_directory:
            # Process file in background thread
            t = threading.Thread(target=process_file, args=(event.src_path,), daemon=True)
            t.start()
    
    def on_moved(self, event):
        if not event.is_directory:
            # Process destination in background thread
            t = threading.Thread(target=process_file, args=(event.dest_path,), daemon=True)
            t.start()


def start_monitoring(watch_paths: list, callback: Optional[Callable] = None) -> Observer:
    """
    Start entropy monitoring in background threads.
    
    Args:
        watch_paths: List of directory paths to monitor
        callback: Optional function to call with alert messages
    
    Returns:
        Observer instance (call .stop() to stop monitoring)
    """
    global observer_instance, baseline, alert_callback
    
    # Stop existing observer if running
    if observer_instance is not None:
        try:
            observer_instance.stop()
            observer_instance.join()
        except:
            pass
    
    # Set global callback
    alert_callback = callback
    
    # Load baseline from disk
    baseline = load_baseline(BASELINE_FILE)
    
    # Create and start observer
    event_handler = EntropyHandler()
    obs = Observer()
    for path in watch_paths:
        obs.schedule(event_handler, path, recursive=True)
    obs.start()
    observer_instance = obs
    
    return obs


def stop_monitoring() -> None:
    """Stop the entropy monitor."""
    global observer_instance, baseline
    
    if observer_instance is not None:
        try:
            observer_instance.stop()
            observer_instance.join()
        except:
            pass
        finally:
            observer_instance = None
    
    # Save baseline on exit
    with lock:
        save_baseline(BASELINE_FILE, baseline)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Entropy-based file change monitor")
    parser.add_argument("paths", nargs="+", help="Paths to monitor (absolute)")
    args = parser.parse_args()
    
    # Add common excludes for Windows and Linux
    if sys.platform.startswith("win"):
        EXCLUDE_DIRS.extend([
            str(Path("C:/Windows").resolve()),
            str(Path("C:/Program Files").resolve()),
            str(Path("C:/Program Files (x86)").resolve())
        ])
    else:
        EXCLUDE_DIRS.extend([
            str(Path("/proc").resolve()),
            str(Path("/sys").resolve()),
            str(Path("/dev").resolve())
        ])
    
    # Load baseline
    baseline = load_baseline(BASELINE_FILE)
    
    # Create and start observer
    event_handler = EntropyHandler()
    obs = Observer()
    for path in args.paths:
        obs.schedule(event_handler, path, recursive=True)
    obs.start()
    
    print("Monitoring paths:", args.paths)
    
    try:
        while True:
            time.sleep(5)
            # Periodically persist baseline
            with lock:
                save_baseline(BASELINE_FILE, baseline)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Entropy-based file change monitor")
    parser.add_argument("paths", nargs="+", help="Paths to monitor (absolute)")
    args = parser.parse_args()
    # add common excludes for Windows and Linux if not provided
    if sys.platform.startswith("win"):
        EXCLUDE_DIRS.extend([str(Path("C:/Windows").resolve()), str(Path("C:/Program Files").resolve()), str(Path("C:/Program Files (x86)").resolve())])
    else:
        EXCLUDE_DIRS.extend([str(Path("/proc").resolve()), str(Path("/sys").resolve()), str(Path("/dev").resolve())])
    main(args.paths)
