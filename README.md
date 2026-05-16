# Phishing URL Detection System

A comprehensive machine learning-based system for detecting phishing URLs using XGBoost classifier with feature engineering and FastAPI backend.

##  Project Structure

```
phishing-url-detection/
├── frontend/                     # React frontend application
├── real time inference/          # FastAPI backend service
│   ├── main.py                   # FastAPI application with prediction endpoints
│   ├── XGBoost.json              # Trained XGBoost model
│   ├── robust_scaler.pkl         # Feature scaler
│   ├── config.json               # Model configuration and feature definitions
│   ├── check_scaler.py           # Utility for checking scaler compatibility
│   └── requirements.txt          # Python dependencies
├── XGBoost model train note book.ipynb  # Model training notebook
└── XGBoost.pkl                   # Alternative model format
```

## Features

- **High Accuracy Detection**: Achieves 99.73% accuracy on test data
- **Real-time Prediction**: FastAPI endpoints for instant URL analysis
- **Comprehensive Feature Extraction**: 60+ URL-based features including:
  - Lexical features (URL length, character ratios)
  - Host-based features (domain entropy, subdomain count)
  - Path and query analysis
  - Security indicators (HTTPS, suspicious TLDs)
  - Brand impersonation detection
- **Interactive History Tracking**: Scan history with filtering capabilities
- **Modern Frontend**: React-based user interface (in development)

## 🔧 Installation

### Backend Setup
```bash
cd "real time inference"
pip install -r requirements.txt
```

### Frontend Setup
```bash
cd frontend
npm install
```

##  Dependencies

### Backend (Python)
- FastAPI
- XGBoost
- scikit-learn (for scaler)
- pandas
- numpy
- joblib
- pydantic
- uvicorn

### Frontend
- React
- Vite
- ESLint

##  Usage

### Start Backend Server
```bash
cd "real time inference"
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Start Frontend Development Server
```bash
cd frontend
npm run dev
```

### API Endpoints

#### Root Endpoint
```bash
GET /
```
Returns API status and model information.

#### Predict Phishing
```bash
POST /predict
Content-Type: application/json

{
  "url": "http://example.com"
}
```

Returns:
```json
{
  "original_url": "http://example.com",
  "scanned_url": "http://www.example.com",
  "is_phishing": false,
  "phishing_rate": 2.34,
  "threshold": 54.91,
  "scan_time": 0.0023,
  "timestamp": "2026-05-16T21:00:26+05:30"
}
```

#### Extract Features
```bash
POST /features
```
Returns detailed feature extraction for analysis.

#### History Management
- `GET /history` - Retrieve scan history
- `DELETE /history` - Clear all history
- `DELETE /history/delete?url=<url>` - Delete specific URL from history

##  Model Performance

Based on test metrics from `config.json`:
- **Accuracy**: 99.73%
- **Precision**: 99.65%
- **Recall**: 99.20%
- **F1-Score**: 99.43%
- **ROC AUC**: 99.94%
- **MCC**: 99.25%

## 🔍 Feature Categories

The model uses 60 features grouped into:

1. **URL Characteristics** (length, entropy, character ratios)
2. **Domain Features** (length, entropy, TLD analysis)
3. **Host Features** (subdomains, IP detection, shortening services)
4. **Path Analysis** (directory structure, file extensions)
5. **Query Parameters** (parameter count, entropy, values)
6. **Security Indicators** (HTTPS, non-standard ports, special characters)
7. **Content Analysis** (phishing keywords, brand impersonation)
8. **Legitimacy Checks** (known legitimate domains)

##  How It Works

1. **URL Preprocessing**: Normalizes URLs (adds www. prefix when appropriate)
2. **Feature Extraction**: Computes 60+ features from URL components
3. **Feature Scaling**: Applies RobustScaler to continuous features
4. **Prediction**: Uses XGBoost classifier to compute phishing probability
5. **Decision**: Compares probability against optimized threshold (0.5491)

##  Training Notebook

See `XGBoost model train note book.ipynb` for:
- Data preprocessing pipeline
- Feature engineering details
- Model training and hyperparameter tuning
- Evaluation metrics and validation
- Feature importance analysis

##  Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 👥 Acknowledgments

- Built with FastAPI for high-performance API endpoints
- Utilizes XGBoost for robust machine learning predictions
- Inspired by phishing detection research and security best practices
