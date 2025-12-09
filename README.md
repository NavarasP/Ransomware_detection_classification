# Ransomware Detector (Static PE Analysis)

This project trains a RandomForest classifier on the Kaggle ransomware dataset and serves a Streamlit web app that scores uploaded Windows PE (`.exe`) files using static header features.

## Setup
1. Create/activate a virtual environment (example on PowerShell):
   ```powershell
   python -m venv .venv; .venv\Scripts\Activate.ps1
   ```
2. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

## Training
1. Ensure Kaggle credentials are configured so `kagglehub` can download `amdj3dax/ransomware-detection-data-set`.
2. Run training to download data, fit the model, and save artifacts under `artifacts/`:
   ```powershell
   python train_model.py
   ```
3. Outputs:
   - `artifacts/random_forest_model.joblib`
   - `artifacts/feature_metadata.json`

## Streamlit App
1. Make sure the artifacts exist (run training once).
2. Launch the app:
   ```powershell
   # if the venv is active
   streamlit run app.py

   # or explicitly with the venv python and no telemetry prompt
   $env:STREAMLIT_BROWSER_GATHER_USAGE_STATS="false"; & ".venv/ Scripts/python.exe" -m streamlit run app.py --server.headless true
   ```
3. Upload a Windows PE (`.exe`) file. The app extracts the required 15 features, predicts **Benign** vs **Ransomware**, shows confidence, MD5, and the extracted feature values.

## Quickstart (one-shot)
```powershell
python -m venv .venv; .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python train_model.py
streamlit run app.py
```

## Current model metrics
- 5-fold CV accuracy: ~0.9968
- Hold-out test accuracy: ~0.9963

## Notes
- The detector uses static analysis only and should support quick triage; do not treat the result as definitive malware assurance.
- Feature expectations match the training notebook: `Machine, DebugSize, DebugRVA, MajorImageVersion, MajorOSVersion, ExportRVA, ExportSize, IatVRA, MajorLinkerVersion, MinorLinkerVersion, NumberOfSections, SizeOfStackReserve, DllCharacteristics, ResourceSize, BitcoinAddresses` (label: `Benign`).
