from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import sys
import os

# Add src/ to path so we can import predict.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
from predict import predict_url
from qr_feature import extract_url_from_qr
from redirect_url import resolve_final_url

app = Flask(__name__)
CORS(app)  # allows React (port 3000) to talk to Flask (port 5000)


@app.route('/')
def home():
    return jsonify({'status': 'PhishGuard API is running!'})


@app.route('/predict_qr',methods=['POST'])
def predict_qr():
    uploaded_file=request.files['qr_image']
    url=extract_url_from_qr(uploaded_file)
    if url is None:
        return jsonify({"error":" no url is found"}),400
    
    # Add http:// if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    url=resolve_final_url(url)

    try:
        result=predict_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/predict', methods=['POST'])
def predict():
    # Get URL from request body
    data = request.get_json()

    if not data or 'url' not in data:
        return jsonify({'error': 'Please provide a URL'}), 400

    url = data['url'].strip()

    if not url:
        return jsonify({'error': 'URL cannot be empty'}), 400

    # Add http:// if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    url=resolve_final_url(url)

    try:
        result = predict_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)