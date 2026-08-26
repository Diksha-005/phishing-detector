# PhishGuard — Hybrid Phishing & Suspicious Website Detection System

> DRDO Internship Project | Hybrid ML System combining Random Forest, XGBoost, and PyTorch Neural Network

---

##  Overview

PhishGuard is a real-time phishing and suspicious website detection system built as part of a DRDO internship project. It analyzes any URL and classifies it as **phishing** or **legitimate** using a 3-model hybrid approach achieving **95.84% accuracy**.

The system extracts 85 features from three sources — URL structure, webpage content, and domain registration data — then combines predictions from three independently trained models into a single risk score.

---

##  Architecture

```
User inputs URL
      ↓
┌─────────────────────────────────────┐
│         Feature Extraction          │
│  ┌───────────────────────────────┐  │
│  │ url_features.py  (53 features)│  │
│  │ content_features.py (27 feats)│  │
│  │ domain_features.py  (5 feats) │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
      ↓ 85 features
┌─────────────────────────────────────┐
│           3-Model Hybrid            │
│  ┌─────────────────────────────┐    │
│  │ Random Forest + XGBoost     │    │
│  │ PyTorch Neural Network      │    │
│  │ (averaged probabilities)    │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
      ↓
  Risk Score + Verdict
  (PHISHING / LEGITIMATE)
```

---

##  Model Performance

| Model | Test Accuracy |
|---|---|
| Random Forest + XGBoost Hybrid | 95.84% |
| PyTorch Neural Network | 96.86% (training) |
| **3-Model Combined Hybrid** | **95.67%** |

> Full-feature lab benchmark (with deprecated Alexa/PageRank APIs): 97.2%
> Deployable live model (self-contained, no deprecated APIs): 95.84%

---

##  Models Used

### 1. Random Forest + XGBoost (Sklearn VotingClassifier)
- Ensemble of 100 decision trees (Random Forest) + gradient boosted trees (XGBoost)
- Soft voting — combines probability outputs from both models
- Trained on 85 URL/content/domain features

### 2. PyTorch Neural Network
- 4-layer fully connected network with ReLU activations and Dropout
- Architecture: `Input(85) → 128 → 64 → 32 → Output(1)`
- Trained with BCEWithLogitsLoss + Adam optimizer (lr=0.001)
- Manual implementation: forward pass, loss, backward pass, zero gradients, step

### 3. Combined Hybrid
- Averages phishing probabilities from both models
- Final risk score = `(sklearn_prob + pytorch_prob) / 2 × 100`

---

## 📁 Project Structure

```
phishing_detector/
│
├── data/
│   └── dataset.csv              ← 11,430 labeled URLs (balanced)
│
├── models/
│   ├── hybrid_model.pkl         ← trained RF + XGBoost model
│   ├── pytorch_model.pth        ← trained Neural Network weights
│   ├── scaler.pkl               ← StandardScaler for PyTorch preprocessing
│   └── feature_names.pkl        ← ordered list of 85 feature names
│
├── src/
│   ├── url_features.py          ← extracts 53 URL string features
│   ├── content_features.py      ← extracts 27 webpage HTML features
│   ├── domain_features.py       ← extracts 5 WHOIS/DNS/Tranco features
│   ├── predict.py               ← full prediction pipeline
│   └── phishing_detector.ipynb  ← training notebook
│
├── frontend/                    ← React frontend (by @pariarora2526)
│
├── app.py                       ← Flask API backend
├── requirements.txt             ← Python dependencies
└── README.md
```

---

## ⚙️ Feature Extraction

### Group 1 — URL String Features (53 features, `url_features.py`)
Extracted purely from the URL text — no network calls needed.
Examples: `length_url`, `nb_dots`, `nb_hyphens`, `has_https`, `nb_subdomains`, `phish_hints`, `brand_in_path`, `suspecious_tld`

### Group 2 — Webpage Content Features (27 features, `content_features.py`)
Extracted by visiting the actual webpage and parsing HTML.
Examples: `login_form`, `iframe`, `external_favicon`, `sfh`, `popup_window`, `ratio_extHyperlinks`, `onmouseover`

### Group 3 — Domain Features (5 features, `domain_features.py`)
Extracted via WHOIS lookups, DNS resolution, and Tranco ranking API.
Examples: `domain_age`, `domain_registration_length`, `web_traffic`, `dns_record`, `whois_registered_domain`

> **Note:** `page_rank` and `google_index` were excluded from the live model as they rely on deprecated/inaccessible APIs (Alexa rank discontinued, Google index requires scraping). `web_traffic` was recovered using the free [Tranco list](https://tranco-list.eu/) as an academic Alexa replacement.

---

## 🚀 Setup & Installation

### Prerequisites
- Python 3.11+
- Node.js (for React frontend)

### 1. Clone the repository
```bash
git clone https://github.com/Diksha-005/phishing-detector.git
cd phishing-detector
```

### 2. Create and activate virtual environment
```bash
python -m venv env1
env1\Scripts\activate      # Windows
source env1/bin/activate   # Mac/Linux
```

### 3. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 4. Run Flask backend
```bash
python app.py
```
Flask API will start at `http://localhost:5000`

### 5. Run React frontend
```bash
cd frontend
npm install
npm start
```
React app will start at `http://localhost:3000`

---

## 🔌 API Reference

### `POST /predict`

Analyzes a URL and returns a phishing verdict with risk score.

**Request:**
```json
{
  "url": "http://suspicious-login.xyz/verify"
}
```

**Response:**
```json
{
  "url": "http://suspicious-login.xyz/verify",
  "verdict": "PHISHING",
  "risk_score": 95.49,
  "sklearn_phishing_prob": 90.99,
  "sklearn_legitimate_prob": 9.01,
  "pytorch_phishing_prob": 100.0,
  "pytorch_legitimate_prob": 0.0,
  "final_phishing_prob": 95.49,
  "final_legitimate_prob": 4.51
}
```

**Verdict values:** `"PHISHING"` or `"LEGITIMATE"`

> ⚠️ Analysis takes 15–30 seconds per URL as it performs live webpage fetching, WHOIS lookups, and DNS resolution.

---

## 📦 Dataset

- **Source:** [Web Page Phishing Detection Dataset](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset) (Kaggle)
- **Size:** 11,430 URLs (5,715 phishing + 5,715 legitimate — perfectly balanced)
- **Features:** 88 pre-extracted features (85 used after dropping 3 deprecated API-dependent features)
- **Missing values:** None

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| ML Models | Scikit-learn, XGBoost, PyTorch |
| Feature Extraction | tldextract, BeautifulSoup, python-whois, Tranco |
| Backend API | Flask, Flask-CORS |
| Frontend | React |
| Data Processing | Pandas, NumPy |
| Model Persistence | Pickle, PyTorch state_dict |

---

## 👥 Team

| Role | Contributor |
|---|---|
| ML Pipeline + Flask API | Diksha |
| React Frontend | Pari Arora |

---

## 📄 License

This project was developed as part of a DRDO internship. All rights reserved.

