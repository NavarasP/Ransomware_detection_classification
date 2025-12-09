from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, Sequence, Tuple, runtime_checkable
import json
import tempfile
import os
import subprocess
import threading
import queue
from pathlib import Path
from datetime import datetime

import joblib
import pandas as pd
import streamlit as st

import entropy_monitor
from feature_extractor import FEATURE_COLUMNS, compute_md5, extract_features
from file_handler import FileHandler
from virustotal import VirusTotalAPI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Silence Pylance noise for unknown members/vars from third-party stubs
# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

if TYPE_CHECKING:  # pragma: no cover
    pass


@runtime_checkable
class EstimatorProtocol(Protocol):
    def predict(self, X: Any) -> Any: ...

    def predict_proba(self, X: Any) -> Any: ...

    @property
    def classes_(self) -> Sequence[Any]: ...


MODEL_PATH = Path("artifacts/random_forest_model.joblib")
META_PATH = Path("artifacts/feature_metadata.json")


@st.cache_resource(show_spinner=False)
def load_model() -> Tuple[EstimatorProtocol, list[str]]:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "Model artifact not found. Run `python train_model.py` to train and save the model first."
        )

    loaded: Any = joblib.load(MODEL_PATH)
    model: EstimatorProtocol = loaded  # runtime assumed compatible
    feature_order = FEATURE_COLUMNS
    if META_PATH.exists():
        try:
            meta = json.loads(META_PATH.read_text())
            feature_order = meta.get("feature_columns", FEATURE_COLUMNS)
        except Exception:
            feature_order = FEATURE_COLUMNS
    return model, feature_order


def format_prediction(label: int) -> str:
    return "Benign" if label == 1 else "Ransomware"


def init_session_state():
    """Initialize session state variables"""
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = []
    if 'vt_api' not in st.session_state:
        st.session_state.vt_api = None


def get_vt_api() -> VirusTotalAPI | None:
    """Get or create VirusTotal API instance"""
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    
    if not api_key:
        return None
    
    if st.session_state.vt_api is None:
        st.session_state.vt_api = VirusTotalAPI(api_key)
    
    return st.session_state.vt_api


def main():
    st.set_page_config(
        page_title="Ransomware Detection & VirusTotal Scanner",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Auto-refresh for entropy monitoring page only
    if 'entropy_monitoring' in st.session_state and st.session_state.entropy_monitoring:
        import time
        # Add a rerun trigger every 3 seconds
        if 'last_update' not in st.session_state:
            st.session_state.last_update = time.time()
        
        current_time = time.time()
        if current_time - st.session_state.last_update > 3:
            st.session_state.last_update = current_time
            st.rerun()
    
    init_session_state()
    
    # Check for VirusTotal API key
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    vt_available = bool(api_key)
    
    # Sidebar Navigation
    st.sidebar.title("🛡️ Scanner")
    st.sidebar.markdown("---")
    
    if not vt_available:
        st.sidebar.warning(
            "⚠️ VirusTotal API key not found in `.env` file\n\n"
            "Create a `.env` file with:\n"
            "`VIRUSTOTAL_API_KEY=your_key_here`\n\n"
            "Get your free API key from https://www.virustotal.com/"
        )
        st.sidebar.markdown("---")
        page = st.sidebar.radio("Navigation", ["🔬 Ransomware Detector", "📈 Entropy Monitor"])
    else:
        page = st.sidebar.radio("Navigation", ["🔬 Ransomware Detector", "📈 Entropy Monitor", "🔍 VirusTotal Scanner", "🎯 Combined Analysis", "📊 Results"])
    
    # Main title
    st.title("🛡️ Ransomware Detection & VirusTotal Scanner")
    st.markdown("Comprehensive file analysis using static ML and cloud-based threat intelligence")
    st.markdown("---")
    
    # PAGE ROUTING
    if page == "🔬 Ransomware Detector":
        st.subheader("🔬 Ransomware Detector (Static PE Analysis)")
        st.markdown(
            "Upload a Windows PE (.exe) file to predict if it is benign or ransomware "
            "using static header feature analysis."
        )
        
        with st.expander("How it works", expanded=False):
            st.markdown(
                """
                - Extracts static header features from the PE file (no execution).
                - Feeds features to a RandomForest model trained on the Kaggle dataset.
                - Outputs a binary label plus model confidence.
                - **Safe**: Does not execute the file or require network access.
                """
            )
        
        uploaded = st.file_uploader("Upload a PE (.exe) file", type=["exe"], key="ransomware_upload")
        
        if uploaded:
            try:
                model, feature_order = load_model()
            except FileNotFoundError as exc:
                st.error(str(exc))
                return
            
            with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
                tmp.write(uploaded.getbuffer())
                tmp_path = Path(tmp.name)
            
            try:
                feats = extract_features(tmp_path)
                md5 = compute_md5(tmp_path)
                df = pd.DataFrame([feats])
                
                missing = [c for c in feature_order if c not in df.columns]
                if missing:
                    st.error(f"Extractor missing expected features: {missing}")
                    return
                
                df = df[feature_order]
                prediction = int(model.predict(df)[0])
                
                proba = None
                if hasattr(model, "predict_proba"):
                    classes = list(getattr(model, "classes_", []))
                    class_index = classes.index(1) if classes and 1 in classes else 0
                    probs = model.predict_proba(df)[0]
                    proba = float(probs[class_index]) if probs is not None else None
                
                # Results display
                st.subheader("📋 Analysis Result")
                
                col1, col2, col3 = st.columns(3)
                
                label_text = format_prediction(prediction)
                with col1:
                    if label_text == "Ransomware":
                        st.error(f"**Prediction**: {label_text}")
                    else:
                        st.success(f"**Prediction**: {label_text}")
                
                with col2:
                    if proba is not None:
                        st.metric("Confidence", f"{proba:.2%}")
                
                with col3:
                    st.metric("File Hash (MD5)", md5[:12] + "...")
                
                st.divider()
                
                # Full hash display
                st.text_area("Full MD5 Hash:", value=md5, disabled=True, height=60)
                
                # Store for combined analysis
                st.session_state.ransomware_result = {
                    'file_name': uploaded.name,
                    'prediction': label_text,
                    'confidence': proba,
                    'md5': md5,
                    'features': df.to_dict('records')[0]
                }
                
                # Features table
                with st.expander("📊 Extracted Features", expanded=False):
                    st.dataframe(df.T.rename(columns={0: "value"}), width='stretch')
                
            except Exception as exc:
                st.error(f"Failed to analyze file: {exc}")
            finally:
                try:
                    tmp_path.unlink(missing_ok=True)
                except Exception:
                    pass
        else:
            st.info("👆 Upload a PE file to begin analysis")
        
        st.caption("⚠️ This tool performs static analysis only; results are for triage, not certification.")
    
    # PAGE 2: VirusTotal Scanner
    elif page == "🔍 VirusTotal Scanner":
        if vt_available:
            st.subheader("🔍 VirusTotal File Scanner")
            st.markdown("Scan files and folders using the VirusTotal API for comprehensive threat intelligence")
            
            vt_api = get_vt_api()
            
            if not vt_api:
                st.error("Failed to initialize VirusTotal API")
            else:
                # Sub-tabs for different scanning modes
                vt_mode = st.radio(
                    "Select scanning mode:",
                    ["📄 Single File", "📁 Folder Scan"],
                    horizontal=True,
                    key="vt_mode"
                )
                
                st.divider()
                
                if vt_mode == "📄 Single File":
                    st.subheader("Scan Single File")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        file_input_method = st.radio(
                            "File source:",
                            ["Upload File", "File Path"],
                            key="file_input_method"
                        )
                    
                    if file_input_method == "Upload File":
                        uploaded_vt = st.file_uploader(
                            "Choose a file to scan",
                            key="vt_file_upload"
                        )
                        
                        if uploaded_vt and st.button("🔍 Scan Uploaded File", key="upload_scan_btn"):
                            with st.spinner("Analyzing file with VirusTotal..."):
                                temp_path = f"temp_{uploaded_vt.name}"
                                with open(temp_path, "wb") as f:
                                    f.write(uploaded_vt.getbuffer())
                                
                                try:
                                    file_hash = FileHandler.calculate_sha256(temp_path)
                                    vt_result = vt_api.get_file_status(file_hash)
                                    
                                    st.subheader("VirusTotal Scan Results")
                                    
                                    col1, col2, col3 = st.columns(3)
                                    with col1:
                                        status = vt_result.get('status', 'UNKNOWN')
                                        if status == 'INFECTED':
                                            st.error(f"**Status**: {status}")
                                        elif status == 'CLEAN':
                                            st.success(f"**Status**: {status}")
                                        else:
                                            st.info(f"**Status**: {status}")
                                    
                                    with col2:
                                        st.metric("Malicious", vt_result.get('malicious', '-'))
                                    
                                    with col3:
                                        st.metric("Suspicious", vt_result.get('suspicious', '-'))
                                    
                                    st.divider()
                                    
                                    # Full hash
                                    st.text_area("SHA256 Hash:", value=file_hash, disabled=True, height=60)
                                    
                                    # Detailed results
                                    st.json({
                                        'status': vt_result.get('status'),
                                        'malicious': vt_result.get('malicious'),
                                        'suspicious': vt_result.get('suspicious'),
                                        'undetected': vt_result.get('undetected'),
                                        'harmless': vt_result.get('harmless')
                                    })
                                    
                                    # Store for combined analysis
                                    st.session_state.vt_result = {
                                        'file_name': uploaded_vt.name,
                                        'hash': file_hash,
                                        'status': vt_result.get('status'),
                                        'malicious': vt_result.get('malicious'),
                                        'suspicious': vt_result.get('suspicious')
                                    }
                                    
                                finally:
                                    if os.path.exists(temp_path):
                                        os.remove(temp_path)
                    
                    else:  # File Path
                        file_path = st.text_input(
                            "Enter file path",
                            placeholder="C:\\path\\to\\file.exe",
                            key="vt_file_path"
                        )
                        
                        if file_path and st.button("🔍 Scan File", key="path_scan_btn"):
                            if not os.path.isfile(file_path):
                                st.error(f"File not found: {file_path}")
                            else:
                                with st.spinner("Analyzing file with VirusTotal..."):
                                    try:
                                        file_hash = FileHandler.calculate_sha256(file_path)
                                        vt_result = vt_api.get_file_status(file_hash)
                                        
                                        st.subheader("VirusTotal Scan Results")
                                        
                                        col1, col2, col3 = st.columns(3)
                                        with col1:
                                            status = vt_result.get('status', 'UNKNOWN')
                                            if status == 'INFECTED':
                                                st.error(f"**Status**: {status}")
                                            elif status == 'CLEAN':
                                                st.success(f"**Status**: {status}")
                                            else:
                                                st.info(f"**Status**: {status}")
                                        
                                        with col2:
                                            st.metric("Malicious", vt_result.get('malicious', '-'))
                                        
                                        with col3:
                                            st.metric("Suspicious", vt_result.get('suspicious', '-'))
                                        
                                        st.divider()
                                        
                                        st.text_area("SHA256 Hash:", value=file_hash, disabled=True, height=60)
                                        
                                        st.json({
                                            'status': vt_result.get('status'),
                                            'malicious': vt_result.get('malicious'),
                                            'suspicious': vt_result.get('suspicious'),
                                            'undetected': vt_result.get('undetected'),
                                            'harmless': vt_result.get('harmless')
                                        })
                                        
                                        st.session_state.vt_result = {
                                            'file_name': Path(file_path).name,
                                            'hash': file_hash,
                                            'status': vt_result.get('status'),
                                            'malicious': vt_result.get('malicious'),
                                            'suspicious': vt_result.get('suspicious')
                                        }
                                        
                                    except Exception as e:
                                        st.error(f"Error scanning file: {str(e)}")
                
                else:  # Folder Scan
                    st.subheader("Scan Folder for Malware")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        folder_path = st.text_input(
                            "Enter folder path",
                            placeholder="C:\\Users\\Desktop\\suspicious",
                            key="folder_path_input"
                        )
                        recursive = st.checkbox("Scan recursively", value=True, key="recursive_scan")
                    
                    with col2:
                        st.markdown("**Options:**")
                        save_log = st.checkbox("Save results to log file", value=True, key="save_log_check")
                        
                        if save_log:
                            log_file_path = st.text_input(
                                "Log file path (optional)",
                                placeholder="C:\\Desktop\\vt_results.log",
                                key="log_file_input"
                            )
                        else:
                            log_file_path = None
                    
                    if st.button("🚀 Start Folder Scan", key="folder_scan_btn"):
                        if not folder_path:
                            st.error("Please enter a folder path")
                        elif not os.path.isdir(folder_path):
                            st.error(f"Folder not found: {folder_path}")
                        else:
                            st.session_state.scan_results = []
                            
                            with st.spinner("Scanning files..."):
                                files = FileHandler.get_files_from_directory(folder_path, recursive)
                                
                                if not files:
                                    st.warning("No files found in the specified folder")
                                else:
                                    progress_bar = st.progress(0)
                                    status_placeholder = st.empty()
                                    results_placeholder = st.empty()
                                    
                                    results = []
                                    
                                    for idx, file_path in enumerate(files):
                                        try:
                                            file_hash = FileHandler.calculate_sha256(file_path)
                                            vt_result = vt_api.get_file_status(file_hash)
                                            
                                            formatted_result = FileHandler.format_file_info(
                                                file_path, file_hash, vt_result
                                            )
                                            
                                            result_dict = {
                                                'file': Path(file_path).name,
                                                'path': file_path,
                                                'hash': file_hash[:16] + "...",
                                                'status': vt_result['status'],
                                                'malicious': vt_result.get('malicious', '-'),
                                                'suspicious': vt_result.get('suspicious', '-'),
                                                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                            }
                                            
                                            results.append(result_dict)
                                            st.session_state.scan_results.append(formatted_result)
                                            
                                            progress = (idx + 1) / len(files)
                                            progress_bar.progress(progress)
                                            status_placeholder.text(f"Scanning: {idx + 1}/{len(files)} files")
                                            
                                            with results_placeholder.container():
                                                df_results = pd.DataFrame(results)
                                                st.dataframe(df_results, width='stretch')
                                        
                                        except Exception as e:
                                            st.warning(f"Error scanning {file_path}: {str(e)}")
                                    
                                    if save_log and log_file_path:
                                        try:
                                            os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
                                            with open(log_file_path, 'w') as f:
                                                for result in st.session_state.scan_results:
                                                    f.write(result + "\n")
                                            st.success(f"✅ Results saved to {log_file_path}")
                                        except Exception as e:
                                            st.error(f"Error saving log file: {str(e)}")
                                    
                                    st.success(f"✅ Scan complete! Scanned {len(files)} files")
        else:
            st.error("VirusTotal API not configured. Please add your API key to the `.env` file.")
    
    # PAGE 3: Combined Analysis
    elif page == "🎯 Combined Analysis":
        st.subheader("🎯 Combined Analysis")
        st.markdown(
            "Compare results from both the Static Ransomware Detector and VirusTotal Scanner "
            "for comprehensive file analysis."
        )
        
        st.divider()
        
        has_ransomware = hasattr(st.session_state, 'ransomware_result') and st.session_state.ransomware_result
        has_vt = hasattr(st.session_state, 'vt_result') and st.session_state.vt_result
        
        if not (has_ransomware and has_vt):
            st.info(
                "👆 Run scans in both the **Ransomware Detector** and **VirusTotal Scanner** pages "
                "to see a combined analysis here."
            )
        else:
            rd = st.session_state.ransomware_result
            vt = st.session_state.vt_result
            
            st.subheader("📊 Side-by-Side Comparison")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### 🔬 Static Ransomware Detector")
                st.markdown(f"**File**: {rd.get('file_name', 'N/A')}")
                st.markdown(f"**Prediction**: `{rd.get('prediction', 'N/A')}`")
                if rd.get('confidence'):
                    st.markdown(f"**Confidence**: `{rd.get('confidence'):.2%}`")
                st.text_area("MD5 Hash:", value=rd.get('md5', ''), disabled=True, height=60, key="rd_hash")
            
            with col2:
                st.markdown("### 🔍 VirusTotal Scanner")
                st.markdown(f"**File**: {vt.get('file_name', 'N/A')}")
                st.markdown(f"**Status**: `{vt.get('status', 'N/A')}`")
                st.markdown(f"**Malicious**: `{vt.get('malicious', '-')}`")
                st.markdown(f"**Suspicious**: `{vt.get('suspicious', '-')}`")
                st.text_area("SHA256 Hash:", value=vt.get('hash', ''), disabled=True, height=60, key="vt_hash")
            
            st.divider()
            
            # Risk Assessment
            st.subheader("⚠️ Risk Assessment")
            
            static_risk = "HIGH" if rd.get('prediction') == "Ransomware" else "LOW"
            vt_risk = "HIGH" if vt.get('status') == "INFECTED" else ("MEDIUM" if vt.get('malicious', 0) > 0 else "LOW")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Static Analysis Risk", static_risk)
            
            with col2:
                st.metric("VirusTotal Risk", vt_risk)
            
            with col3:
                overall_risk = "HIGH" if (static_risk == "HIGH" or vt_risk == "HIGH") else "MEDIUM" if vt_risk == "MEDIUM" else "LOW"
                st.metric("Overall Risk", overall_risk)
            
            st.divider()
            
            # Summary
            st.subheader("📝 Analysis Summary")
            
            summary = f"""
            **File**: {rd.get('file_name', 'Unknown')}
            
            **Static Analysis Results**:
            - Prediction: {rd.get('prediction', 'N/A')}
            - Confidence: {f"{rd.get('confidence'):.2%}" if rd.get('confidence') else 'N/A'}
            - Method: ML-based static PE header analysis
            
            **VirusTotal Results**:
            - Status: {vt.get('status', 'N/A')}
            - Malicious Detections: {vt.get('malicious', '-')}
            - Suspicious Detections: {vt.get('suspicious', '-')}
            - Method: Cloud-based threat intelligence database
            
            **Recommendation**:
            """
            
            if static_risk == "HIGH" and vt_risk == "HIGH":
                summary += "🚨 **CRITICAL**: Both methods flagged this file as suspicious. Do NOT execute."
            elif static_risk == "HIGH" or vt_risk == "HIGH":
                summary += "⚠️ **WARNING**: At least one detection method flagged this file. Use caution and isolate for further analysis."
            else:
                summary += "✅ **LOW RISK**: Both methods indicate this file appears to be benign. However, perform additional testing as needed."
            
            st.markdown(summary)
    
    # PAGE 4: Results Summary
    elif page == "📊 Results":
        st.subheader("📊 Scan Results Summary")
        
        if not st.session_state.scan_results:
            st.info("No scan results yet. Run a VirusTotal folder scan to see results here.")
        else:
            st.text(f"Total files scanned: {len(st.session_state.scan_results)}")
            
            st.subheader("Results Log")
            results_text = "\n".join(st.session_state.scan_results)
            st.text_area("Scan Results:", value=results_text, height=400, disabled=True, key="results_textarea")
            
            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    label="📥 Download Results as TXT",
                    data=results_text,
                    file_name=f"vt_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )
            
            with col2:
                if st.button("🗑️ Clear Results", key="clear_results_btn"):
                    st.session_state.scan_results = []
                    st.rerun()
    
    # PAGE 5: Entropy Monitor
    elif page == "📈 Entropy Monitor":
        st.subheader("📈 Real-time Entropy Monitor")
        st.markdown("Monitor file system entropy to detect encryption and suspicious file modifications.")
        
        st.divider()
        
        # Initialize monitoring state
        if 'entropy_observer' not in st.session_state:
            st.session_state.entropy_observer = None
        if 'entropy_monitoring' not in st.session_state:
            st.session_state.entropy_monitoring = False
        if 'entropy_log' not in st.session_state:
            st.session_state.entropy_log = []
        if 'entropy_current_path' not in st.session_state:
            st.session_state.entropy_current_path = None
        if 'entropy_session_id' not in st.session_state:
            st.session_state.entropy_session_id = None
        
        col_left, col_right = st.columns([1, 1.5])
        
        with col_left:
            st.markdown("### Configuration")
            
            monitor_path = st.text_input(
                "Folder path",
                placeholder="C:\\Users\\YourUser\\Documents",
                key="entropy_path_input"
            )
            
            # Single button that toggles monitoring
            if st.session_state.entropy_monitoring:
                button_label = "⏹️ Stop Monitoring"
                button_key = "entropy_toggle_btn"
            else:
                button_label = "▶️ Start Monitoring"
                button_key = "entropy_toggle_btn"
            
            if st.button(button_label, key=button_key, width='stretch'):
                if st.session_state.entropy_monitoring:
                    # Stop monitoring
                    try:
                        entropy_monitor.stop_monitoring()
                        st.session_state.entropy_observer = None
                        st.session_state.entropy_monitoring = False
                        st.info("⏸️ Monitoring stopped")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error stopping monitor: {str(e)}")
                else:
                    # Start monitoring
                    if monitor_path:
                        if os.path.isdir(monitor_path):
                            try:
                                # Generate session ID
                                session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
                                st.session_state.entropy_session_id = session_id
                                st.session_state.entropy_log = []
                                st.session_state.entropy_current_path = os.path.abspath(monitor_path)
                                
                                def alert_callback(msg: str):
                                    st.session_state.entropy_log.append(msg)
                                
                                # Start entropy monitor with session ID
                                observer = entropy_monitor.start_monitoring([monitor_path], alert_callback, session_id)
                                st.session_state.entropy_observer = observer
                                st.session_state.entropy_monitoring = True
                                st.success(f"✅ Monitoring started (Session: {session_id})")
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ Error starting monitor: {str(e)}")
                        else:
                            st.error(f"❌ Folder not found: {monitor_path}")
                    else:
                        st.warning("⚠️ Please enter a folder path")
            
            st.divider()
            
            # Display monitoring status
            if st.session_state.entropy_monitoring:
                st.success("🟢 Monitoring Active")
                st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")
            else:
                st.info("🔴 Monitoring Inactive")
            
            st.divider()
            
            # Load and display baseline data for current session only
            if st.session_state.entropy_session_id:
                session_file = Path(f"entropy_sessions/session_{st.session_state.entropy_session_id}.json")
                if session_file.exists():
                    try:
                        with open(session_file, 'r') as f:
                            session_data_full = json.load(f)
                        
                        session_data = session_data_full.get("files", {})
                        st.markdown("### Baseline Stats")
                        
                        if session_data:
                            # Statistics for current session
                            entropy_values = [e for e in session_data.values() if isinstance(e, (int, float))]
                            
                            col_stat1, col_stat2 = st.columns(2)
                            with col_stat1:
                                st.metric("Files Monitored", len(session_data))
                            with col_stat2:
                                if entropy_values:
                                    st.metric("Avg Entropy", f"{sum(entropy_values)/len(entropy_values):.3f}")
                            
                            if entropy_values:
                                st.metric("Max Entropy", f"{max(entropy_values):.3f}")
                            
                            # Graphical representation - Entropy distribution
                            import plotly.graph_objects as go
                            
                            entropy_vals = sorted([e for e in session_data.values() if isinstance(e, (int, float))])
                            
                            fig = go.Figure()
                            fig.add_trace(go.Histogram(
                                x=entropy_vals,
                                nbinsx=15,
                                name='Entropy Distribution',
                                marker_color='#1f77b4'
                            ))
                            fig.add_vline(x=sum(entropy_vals)/len(entropy_vals) if entropy_vals else 0, 
                                         line_dash="dash", line_color="green", 
                                         annotation_text="Avg", annotation_position="top right")
                            fig.add_vline(x=7.2, 
                                         line_dash="dash", line_color="red", 
                                         annotation_text="Alert Threshold", annotation_position="top")
                            fig.update_layout(
                                title="Entropy Distribution (Current Session)",
                                xaxis_title="Entropy Value",
                                yaxis_title="File Count",
                                height=300,
                                showlegend=False,
                                margin=dict(l=40, r=40, t=40, b=40)
                            )
                            st.plotly_chart(fig, width='stretch')
                            
                            # Download baseline for current session
                            st.download_button(
                                label="📥 Download Session Data",
                                data=json.dumps(session_data, indent=2),
                                file_name=f"entropy_session_{st.session_state.entropy_session_id}.json",
                                mime="application/json",
                                width='stretch'
                            )
                        else:
                            st.info("ℹ️ No data collected yet. Files will appear as they're modified.")
                    except Exception as e:
                        st.error(f"Error reading session data: {str(e)}")
                else:
                    st.info("ℹ️ Session data file not created yet.")
            else:
                st.info("ℹ️ Start monitoring to begin a new session.")
        
        with col_right:
            # Tabs for different views
            tab1, tab2, tab3 = st.tabs(["📊 Current Session", "📋 Real-time Alerts", "📂 Previous Sessions"])
            
            with tab1:
                st.markdown("### Monitored Files (Current Session)")
                
                # Auto-refresh every 3 seconds when monitoring is active
                if st.session_state.entropy_monitoring:
                    import time
                    # Initialize last refresh time
                    if 'last_refresh_time' not in st.session_state:
                        st.session_state.last_refresh_time = time.time()
                    
                    # Check if 3 seconds have passed
                    current_time = time.time()
                    if current_time - st.session_state.last_refresh_time >= 3:
                        st.session_state.last_refresh_time = current_time
                        st.rerun()
                
                if st.session_state.entropy_session_id:
                    session_file = Path(f"entropy_sessions/session_{st.session_state.entropy_session_id}.json")
                    if session_file.exists():
                        try:
                            with open(session_file, 'r') as f:
                                session_data_full = json.load(f)
                            
                            session_data = session_data_full.get("files", {})
                            
                            if session_data:
                                # Create dataframe for display
                                files_data = []
                                for file_path, entropy in session_data.items():
                                    files_data.append({
                                        'File': Path(file_path).name,
                                        'Path': file_path,
                                        'Entropy': round(entropy, 4) if isinstance(entropy, (int, float)) else entropy,
                                        'Status': '🔴 High' if entropy >= 7.2 else '🟢 Normal'
                                    })
                                
                                df = pd.DataFrame(files_data).sort_values('Entropy', ascending=False)
                                # Show subset with most important columns
                                display_df = df[['File', 'Entropy', 'Status']].copy()
                                st.dataframe(display_df, width='stretch', height=400)
                                
                                st.caption(f"📊 {len(files_data)} files • Auto-refreshing every 3s")
                            else:
                                st.info("ℹ️ No files tracked yet. Files will appear as they're modified.")
                        except Exception as e:
                            st.error(f"Error reading session data: {str(e)}")
                    else:
                        st.info("ℹ️ Session data file not created yet.")
                else:
                    st.info("ℹ️ Start monitoring to begin tracking files.")
            
            with tab2:
                st.markdown("### Real-time Alerts")
                
                if st.session_state.entropy_log:
                    log_text = "\n".join(st.session_state.entropy_log[-100:])  # Show last 100 lines
                    st.text_area("Alert Log:", value=log_text, height=350, disabled=True, key="entropy_logs_display")
                    
                    # Download logs
                    col1, col2 = st.columns(2)
                    with col1:
                        full_log = "\n".join(st.session_state.entropy_log)
                        st.download_button(
                            label="📥 Download Alerts",
                            data=full_log,
                            file_name=f"entropy_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                            mime="text/plain",
                            key="entropy_download",
                            width='stretch'
                        )
                    
                    with col2:
                        if st.button("🗑️ Clear Alerts", key="entropy_clear", width='stretch'):
                            st.session_state.entropy_log = []
                            st.rerun()
                else:
                    st.info("ℹ️ No alerts yet. Alerts will appear here when suspicious entropy is detected.")
            
            with tab3:
                st.markdown("### Previous Monitoring Sessions")
                
                # List all available sessions
                sessions = entropy_monitor.list_sessions()
                
                if sessions:
                    for session in sessions:
                        session_id = session["id"]
                        metadata = session.get("metadata", {})
                        file_count = session.get("file_count", 0)
                        
                        with st.expander(f"📁 Session {session_id} - {file_count} files"):
                            col_a, col_b = st.columns(2)
                            with col_a:
                                st.write(f"**Start Time:** {metadata.get('start_time', 'N/A')}")
                                st.write(f"**End Time:** {metadata.get('end_time', 'N/A')}")
                            with col_b:
                                st.write(f"**Path:** {metadata.get('watch_path', 'N/A')}")
                                st.write(f"**Files:** {file_count}")
                            
                            # Show file data
                            session_file = Path(f"entropy_sessions/session_{session_id}.json")
                            if session_file.exists():
                                try:
                                    with open(session_file, 'r') as f:
                                        session_data_full = json.load(f)
                                    
                                    session_files = session_data_full.get("files", {})
                                    
                                    if session_files:
                                        files_data = []
                                        for file_path, entropy in session_files.items():
                                            files_data.append({
                                                'File': Path(file_path).name,
                                                'Entropy': round(entropy, 4),
                                                'Status': '🔴 High' if entropy >= 7.2 else '🟢 Normal'
                                            })
                                        
                                        df = pd.DataFrame(files_data).sort_values('Entropy', ascending=False)
                                        st.dataframe(df, width='stretch', height=200)
                                        
                                        # Download button
                                        st.download_button(
                                            label="📥 Download Session",
                                            data=json.dumps(session_data_full, indent=2),
                                            file_name=f"session_{session_id}.json",
                                            mime="application/json",
                                            key=f"download_{session_id}"
                                        )
                                except Exception as e:
                                    st.error(f"Error loading session: {str(e)}")
                else:
                    st.info("ℹ️ No previous sessions found. Start monitoring to create a new session.")
    
    st.divider()
    st.caption(
        "⚠️ This tool is for security analysis and research only. "
        "Results are for triage; not a substitute for professional security assessment. "
        "Always follow proper malware handling procedures."
    )


if __name__ == "__main__":
    main()
