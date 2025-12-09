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
SESSIONS_DIR = "entropy_sessions"  # Directory to store session data
EXCLUDE_EXT = {'.zip', '.rar', '.7z', '.gz', '.jpg', '.jpeg', '.png', '.mp4', '.mp3', '.iso'}
EXCLUDE_DIRS = []  # add system dirs here (absolute paths)
# -------------------------------

lock = threading.Lock()
last_event_time = defaultdict(float)
observer_instance: Optional[Observer] = None
baseline: dict = {}
alert_callback: Optional[Callable] = None
current_session_id: Optional[str] = None
current_session_path: Optional[str] = None

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


def get_session_file(session_id: str) -> str:
    """Get the path for a session file."""
    if not os.path.exists(SESSIONS_DIR):
        os.makedirs(SESSIONS_DIR)
    return os.path.join(SESSIONS_DIR, f"session_{session_id}.json")


def save_session_metadata(session_id: str, metadata: dict) -> None:
    """Save session metadata."""
    session_file = get_session_file(session_id)
    try:
        with open(session_file, 'r') as f:
            session_data = json.load(f)
    except:
        session_data = {"files": {}}
    
    session_data["metadata"] = metadata
    
    try:
        with open(session_file + ".tmp", 'w') as f:
            json.dump(session_data, f, indent=2)
        os.replace(session_file + ".tmp", session_file)
    except Exception:
        pass


def list_sessions() -> list:
    """List all available sessions."""
    if not os.path.exists(SESSIONS_DIR):
        return []
    
    sessions = []
    for file in os.listdir(SESSIONS_DIR):
        if file.startswith("session_") and file.endswith(".json"):
            session_id = file.replace("session_", "").replace(".json", "")
            try:
                with open(os.path.join(SESSIONS_DIR, file), 'r') as f:
                    data = json.load(f)
                    sessions.append({
                        "id": session_id,
                        "metadata": data.get("metadata", {}),
                        "file_count": len(data.get("files", {}))
                    })
            except:
                pass
    
    return sorted(sessions, key=lambda x: x.get("metadata", {}).get("start_time", ""), reverse=True)


def process_file(file_path: str) -> None:
    """
    Process a file, calculate entropy, check thresholds, and update baseline.
    Uses global baseline dict and alert_callback.
    """
    global baseline, alert_callback, current_session_id
    
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
        
        # Update baseline in memory and save to session file
        with lock:
            baseline[abs_path] = entropy
            
            # Save to session file if session is active
            if current_session_id:
                session_file = get_session_file(current_session_id)
                try:
                    with open(session_file, 'r') as f:
                        session_data = json.load(f)
                except:
                    session_data = {"files": {}, "metadata": {}}
                
                session_data["files"][abs_path] = entropy
                
                try:
                    with open(session_file + ".tmp", 'w') as f:
                        json.dump(session_data, f, indent=2)
                    os.replace(session_file + ".tmp", session_file)
                except Exception:
                    pass
        
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


def start_monitoring(watch_paths: list, callback: Optional[Callable] = None, session_id: Optional[str] = None) -> Observer:
    """
    Start entropy monitoring in background threads.
    
    Args:
        watch_paths: List of directory paths to monitor
        callback: Optional function to call with alert messages
        session_id: Optional session ID for storing data separately
    
    Returns:
        Observer instance (call .stop() to stop monitoring)
    """
    global observer_instance, baseline, alert_callback, current_session_id, current_session_path
    
    # Stop existing observer if running
    if observer_instance is not None:
        try:
            observer_instance.stop()
            observer_instance.join()
        except:
            pass
    
    # Set global callback and session
    alert_callback = callback
    current_session_id = session_id
    current_session_path = watch_paths[0] if watch_paths else None
    
    # Initialize baseline for this session
    baseline = {}
    
    # Save session metadata
    if session_id:
        import datetime
        metadata = {
            "start_time": datetime.datetime.now().isoformat(),
            "watch_path": watch_paths[0] if watch_paths else None
        }
        save_session_metadata(session_id, metadata)
    
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
    global observer_instance, baseline, current_session_id
    
    if observer_instance is not None:
        try:
            observer_instance.stop()
            observer_instance.join()
        except:
            pass
        finally:
            observer_instance = None
    
    # Save final session data
    if current_session_id:
        import datetime
        session_file = get_session_file(current_session_id)
        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)
        except:
            session_data = {"files": {}, "metadata": {}}
        
        session_data["metadata"]["end_time"] = datetime.datetime.now().isoformat()
        
        try:
            with open(session_file + ".tmp", 'w') as f:
                json.dump(session_data, f, indent=2)
            os.replace(session_file + ".tmp", session_file)
        except Exception:
            pass
        
        current_session_id = None
