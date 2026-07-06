import json
import pickle
import torch
import numpy as np
import pandas as pd
from torch import nn

from url_features import extract_url_features
from content_features import extract_content_features
from domain_features import extract_domain_features


# ── Neural Network Architecture (must match exactly what we trained) ──
class PhishingNN(nn.Module):
    def __init__(self, input_size):
        super(PhishingNN, self).__init__()
        self.layers = nn.Sequential(
            nn.Linear(input_size, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1)
        )

    def forward(self, x):
        return self.layers(x)


# ── Load all saved models (done once at startup) ──────────────────────
# print("Loading models...")

# with open('models/hybrid_model.pkl', 'rb') as f:
#     sklearn_model = pickle.load(f)

# with open('models/scaler.pkl', 'rb') as f:
#     scaler = pickle.load(f)

# with open('models/feature_names.pkl', 'rb') as f:
#     feature_names = pickle.load(f)

# # Load PyTorch model
# pytorch_model = PhishingNN(input_size=len(feature_names))
# pytorch_model.load_state_dict(torch.load('models/pytorch_model.pth',
#                                weights_only=True))
# pytorch_model.eval()



import os

# Get the directory where predict.py lives (src/)
# Then go up one level to project root, then into models/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, 'models')

print("Loading models...")
print(f"Looking in: {MODELS_DIR}")

with open(os.path.join(MODELS_DIR, 'hybrid_model.pkl'), 'rb') as f:
    sklearn_model = pickle.load(f)

with open(os.path.join(MODELS_DIR, 'scaler.pkl'), 'rb') as f:
    scaler = pickle.load(f)

with open(os.path.join(MODELS_DIR, 'feature_names.pkl'), 'rb') as f:
    feature_names = pickle.load(f)

# Load PyTorch model
pytorch_model = PhishingNN(input_size=len(feature_names))
pytorch_model.load_state_dict(torch.load(
    os.path.join(MODELS_DIR, 'pytorch_model.pth'),
    weights_only=True
))
pytorch_model.eval()

print(f"All models loaded!")
print(f"Expected features: {len(feature_names)}")


# ── Main prediction function ──────────────────────────────────────────
def predict_url(url):
    print(f"\nAnalyzing: {url}")

    # Step 1: Extract all features
    print("   Extracting URL features...")
    url_feats = extract_url_features(url)

    print("   Extracting content features...")
    content_feats = extract_content_features(url)

    print("   Extracting domain features...")
    domain_feats = extract_domain_features(url)

    # Step 2: Combine all features into one dictionary
    all_features = {}
    all_features.update(url_feats)
    all_features.update(content_feats)
    all_features.update(domain_feats)

    # Step 3: Convert to DataFrame with exact column order model expects
    feature_df = pd.DataFrame([all_features], columns=feature_names)

    # Step 4: Handle any missing features (fill with 0 as safe default)
    feature_df = feature_df.fillna(0)

    # Step 5: Get sklearn hybrid model prediction (RF + XGBoost)
    sklearn_prob = sklearn_model.predict_proba(feature_df)[0][1]

    # Step 6: Get PyTorch model prediction
    scaled_features = scaler.transform(feature_df)
    tensor_features = torch.FloatTensor(scaled_features)
    with torch.inference_mode():
        pytorch_logits = pytorch_model(tensor_features)
        pytorch_prob = torch.sigmoid(pytorch_logits).item()

    # Step 7: Combine both predictions (average probabilities)
    final_prob = (sklearn_prob + pytorch_prob) / 2
    final_label = 'PHISHING' if final_prob > 0.5 else 'LEGITIMATE'

    # Step 8: Risk score (0-100)
    risk_score = round(final_prob * 100, 2)

    print(f"\n{'='*45}")
    print(f"   URL: {url}")
    print(f"   Verdict:    {final_label}")
    print(f"   Risk Score: {risk_score}%")
    print(f"   SK Prob:    {round(sklearn_prob*100, 2)}%")
    print(f"   NN Prob:    {round(pytorch_prob*100, 2)}%")
    print(f"{'='*45}")

    return {
    'url': url,
    'verdict': 'PHISHING' if final_prob > 0.5 else 'LEGITIMATE',
    'risk_score': risk_score,
    'sklearn_phishing_prob': round(sklearn_prob * 100, 2),
    'sklearn_legitimate_prob': round((1 - sklearn_prob) * 100, 2),
    'pytorch_phishing_prob': round(pytorch_prob * 100, 2),
    'pytorch_legitimate_prob': round((1 - pytorch_prob) * 100, 2),
    'final_phishing_prob': risk_score,
    'final_legitimate_prob': round((1 - final_prob) * 100, 2)
}


# ---- TEST ----
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.xyz/verify?user=abc@gmail.com",
        "http://192.168.1.1/bank/login"
    ]

    for url in test_urls:
        result = predict_url(url)
        print("\n Returned JSON:")
        print(json.dumps(result, indent=2))  