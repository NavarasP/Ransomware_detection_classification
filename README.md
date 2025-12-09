# 🛡️ Ransomware Detection & VirusTotal Scanner

A comprehensive integrated system for analyzing files using two complementary approaches:

1. **🔬 Static Ransomware Detector**: ML-based analysis using static PE header features
2. **🔍 VirusTotal Scanner**: Cloud-based threat intelligence with 70+ antivirus engines

This project combines a RandomForest classifier (trained on the Kaggle ransomware dataset) with the VirusTotal API to provide both offline static analysis and cloud-based threat intelligence in a single Streamlit web application.

## Features

### 🔬 Static Ransomware Detector
- **Fast Offline Analysis**: No network required, analyzes files in seconds
- **ML-Based Classification**: Random Forest model with ~99.6% accuracy
- **Safe Analysis**: Extracts static PE header features, never executes files
- **Detailed Results**: Shows prediction, confidence score, and extracted features
- **Single or Batch**: Analyze individual files through the web interface

### 🔍 VirusTotal Scanner
- **Cloud Threat Intelligence**: Check against 70+ antivirus engines
- **Folder Scanning**: Recursively scan entire directories
- **Single File Scanning**: Upload files or provide file paths
- **Real-time Results**: Live progress tracking during scans
- **Export Capabilities**: Download results as TXT or CSV
- **Log File Saving**: Automatic logging of scan results

### 🎯 Combined Analysis
- **Side-by-Side Comparison**: View both analysis methods simultaneously
- **Risk Assessment**: Unified risk scoring from both methods
- **Detailed Summary**: Integrated recommendations based on all data
- **Confidence Metrics**: Combined confidence and detection metrics

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Kaggle API credentials (for training; not needed for inference)
- VirusTotal API key (free account, optional for cloud scanning)

### Step 1: Clone/Setup Project

```powershell
cd "d:\Projects\buck\Ransomware_detection_classification"
```

### Step 2: Create Virtual Environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 4: Train Model (First Time Only)

Ensure your Kaggle credentials are configured, then:

```powershell
python train_model.py
```

This downloads the Kaggle ransomware dataset and trains the model. Outputs:
- `artifacts/random_forest_model.joblib` - Trained RandomForest model
- `artifacts/feature_metadata.json` - Feature metadata

### Step 5: Setup VirusTotal API (Optional)

1. Create a `.env` file in the project root:
   ```powershell
   Copy-Item .env.example .env
   ```

2. Edit `.env` and add your VirusTotal API key:
   ```
   VIRUSTOTAL_API_KEY=your_api_key_here
   ```

3. Get your free API key:
   - Visit https://www.virustotal.com/
   - Create a free account
   - Navigate to your API key settings
   - Copy your API key into the `.env` file

### Step 6: Run the Application

```powershell
streamlit run app.py
```

The app will open in your browser at `http://localhost:8501`

## Usage Guide

### 🔬 Ransomware Detector Tab

1. Click on **🔬 Ransomware Detector** tab
2. Upload a Windows PE (`.exe`) file
3. View results:
   - **Prediction**: Benign or Ransomware
   - **Confidence**: Model confidence percentage
   - **File Hash**: MD5 hash of the file
   - **Features**: Extracted PE header features (expandable)

### 🔍 VirusTotal Scanner Tab (Requires API Key)

#### Single File Scan
1. Click on **🔍 VirusTotal Scanner** tab
2. Select **📄 Single File** mode
3. Choose to upload or provide file path
4. Click **🔍 Scan File** or **🔍 Scan Uploaded File**
5. View detailed results from VirusTotal

#### Folder Scan
1. Select **📁 Folder Scan** mode
2. Enter folder path (e.g., `C:\Users\Desktop\suspicious`)
3. Check **Scan recursively** for subfolders
4. Optionally enable **Save results to log file**
5. Click **🚀 Start Folder Scan**
6. Monitor progress and view real-time results

### 🎯 Combined Analysis Tab

1. Run a scan with **Ransomware Detector** tab
2. Run a scan with **VirusTotal Scanner** tab (same file)
3. Go to **🎯 Combined Analysis** tab
4. View side-by-side comparison and unified risk assessment

### 📊 Results Tab

View all VirusTotal folder scan results:
- Summary statistics
- Detailed results log
- Download results as TXT
- Clear results for new scan

## Output Format

### Ransomware Detector Results
```
Prediction: [Benign | Ransomware]
Confidence: 95.2%
MD5: abc123def456...
```

### VirusTotal Results
```
Status: [INFECTED | CLEAN | UNKNOWN]
Malicious: 5
Suspicious: 2
Harmless: 63
Undetected: 2
```

### Combined Analysis Format
```
File: malware.exe

Static Analysis Results:
- Prediction: Ransomware
- Confidence: 87.3%
- Method: ML-based static PE header analysis

VirusTotal Results:
- Status: INFECTED
- Malicious Detections: 5
- Suspicious Detections: 2
- Method: Cloud-based threat intelligence database

Recommendation: 🚨 CRITICAL - Both methods flagged this file as suspicious. Do NOT execute.
```

## Configuration

### API Rate Limiting

VirusTotal API free tier limits:
- **Free Account**: 4 requests per minute
- **Premium Account**: Higher limits available

The app respects these limits. For large folder scans:
- Free tier may encounter rate limiting
- Consider adding strategic delays between requests
- Upgrade to premium for high-volume scanning

### Environment Variables

Create a `.env` file with:
```
VIRUSTOTAL_API_KEY=your_api_key_here
```

See `.env.example` for template.

## Model Information

### Training Data
- **Dataset**: Kaggle Ransomware Detection Data Set
- **Size**: ~10,000+ samples
- **Features**: 15 static PE header features

### Model Performance
- **5-fold Cross-Validation Accuracy**: ~99.68%
- **Hold-out Test Accuracy**: ~99.63%
- **Model Type**: Random Forest Classifier
- **Artifacts Location**: `artifacts/`

### Extracted Features
The model extracts 15 key features from PE file headers:
- Machine type and subsystem
- Section counts and sizes
- DLL characteristics
- Entry point and preferred base address
- File alignment properties
- And more...

## Troubleshooting

### "Model artifact not found"
- **Solution**: Run `python train_model.py` first to train and save the model

### "VirusTotal API key not found"
- **Solution**: Create `.env` file with your API key (optional, Ransomware Detector will still work)

### "Invalid API Key" Error
- Verify your API key is correct
- Ensure your VirusTotal account is active
- Confirm you've entered the key correctly in `.env`

### "File not found in VirusTotal database"
- The file hasn't been analyzed by VirusTotal yet
- New or custom files may not be in the database
- Try uploading the file to VirusTotal's website directly

### Rate Limit Issues
- **Free API**: Limited to 4 requests/minute
- **Solution 1**: Wait a minute before scanning more files
- **Solution 2**: Upgrade to VirusTotal premium for higher limits
- **Solution 3**: Reduce folder scan size

### "Failed to extract features"
- File may be corrupted or not a valid PE file
- Try uploading a different file
- Ensure the file is a Windows PE (`.exe`) file

## Security Considerations

⚠️ **Important Security Notes**:

1. **API Key Security**: 
   - Never commit `.env` file to version control
   - Never share your API key
   - Use `.env.example` for public repos

2. **File Privacy**: 
   - VirusTotal stores analyzed files in their database
   - Be cautious when scanning sensitive files
   - Consider privacy implications before uploading

3. **Not a Replacement**: 
   - This tool supplements antivirus software
   - Does not replace professional security tools
   - Use for triage and analysis only

4. **Malware Handling**:
   - Always use proper isolation procedures
   - Use virtual machines for suspected malware
   - Follow security best practices

## Performance Tips

- **Batch Operations**: Larger scans may take time due to API rate limits
- **File Size**: Scanning speed depends on file size (for hashing) and API response time
- **Network**: Faster internet provides better VirusTotal performance
- **API Tier**: Premium API keys have higher rate limits
- **Caching**: Results are cached in session state for faster repeat scans

## Project Structure

```
Ransomware_detection_classification/
├── app.py                          # Main Streamlit application
├── feature_extractor.py            # PE feature extraction logic
├── file_handler.py                 # File handling and hashing utilities
├── virustotal.py                   # VirusTotal API wrapper
├── train_model.py                  # Model training script
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment variables template
├── pyrightconfig.json              # Pyright configuration
├── README.md                       # This file
├── artifacts/
│   ├── random_forest_model.joblib # Trained model
│   └── feature_metadata.json       # Feature metadata
└── __pycache__/                    # Python cache
```

## Quickstart (One-Shot)

```powershell
# Create virtual environment and install
python -m venv .venv; .venv\Scripts\Activate.ps1; pip install -r requirements.txt

# Train model (first time only)
python train_model.py

# Setup VirusTotal (optional)
Copy-Item .env.example .env
# Edit .env and add your API key

# Run the app
streamlit run app.py
```

## Changelog

### Version 2.0.0 - Integrated System
- ✨ Added VirusTotal Scanner with folder and single file scanning
- ✨ Added Combined Analysis tab for comparing both methods
- ✨ Enhanced UI with tabbed interface
- ✨ Added real-time progress tracking for folder scans
- ✨ Added results export (TXT format)
- ✨ Added log file saving capability
- 🔧 Refactored for modular architecture
- 📚 Comprehensive documentation updates

### Version 1.0.0 - Initial Release
- Initial Ransomware Detector with static PE analysis
- RandomForest model with ~99.6% accuracy
- Streamlit web interface
- Single file scanning

## License

This project is provided as-is for educational and security research purposes.

## Support

For issues with:
- **VirusTotal API**: Visit https://www.virustotal.com/documentation/
- **Streamlit**: Visit https://docs.streamlit.io/
- **Python/Dependencies**: Check PyPI documentation
- **This Project**: Review the README and troubleshooting section

## Disclaimer

⚠️ **Legal & Security Disclaimer**:

This tool is designed for security research, analysis, and triage only. Users are responsible for:
- Complying with all applicable laws and regulations
- Obtaining proper authorization before analyzing files
- Following responsible disclosure practices
- Using proper isolation and containment procedures
- Not using this tool for malicious purposes

Always follow proper malware handling procedures and security best practices.

---

**Remember**: This integrated system provides two complementary analysis methods. Use both approaches together for comprehensive file evaluation. Results are for triage; always perform additional verification as needed.
- Feature expectations match the training notebook: `Machine, DebugSize, DebugRVA, MajorImageVersion, MajorOSVersion, ExportRVA, ExportSize, IatVRA, MajorLinkerVersion, MinorLinkerVersion, NumberOfSections, SizeOfStackReserve, DllCharacteristics, ResourceSize, BitcoinAddresses` (label: `Benign`).
