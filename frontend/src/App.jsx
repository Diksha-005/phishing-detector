import { useState } from "react";
import "./App.css";

function App() {
  // Stores the URL entered by the user
  const [url, setUrl] = useState("");

  // Stores the prediction received from the backend
  const [result, setResult] = useState(null);

  // Controls loading spinner while scanning
  const [loading, setLoading] = useState(false);

  // Stores the last 5 scanned URLs
  const [history, setHistory] = useState([]);

  // Stores the uploaded QR image
  const [selectedFile, setSelectedFile] = useState(null);

  // Stores the preview of the uploaded QR image
  const [preview, setPreview] = useState(null);

  // =========================
  // Scan URL Function
  // =========================
  async function handleScan() {
    // Prevent scanning if input is empty
    if (!url.trim()) {
      alert("Please enter a URL");
      return;
    }

    try {
      // Start loading
      setLoading(true);

      // Send URL to Flask backend
      const response = await fetch("http://127.0.0.1:5000/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      });

      // Receive prediction
      const data = await response.json();

      // Stop loading
      setLoading(false);

      console.log("Prediction Result:", data);

      // Save result
      setResult(data);

      // Save latest scan in history (maximum 5)
      setHistory((prev) => [
        {
          url: url,
          verdict: data.verdict,
        },
        ...prev,
      ].slice(0, 5));
    } catch (error) {
      setLoading(false);

      console.error(error);

      alert("Could not connect to backend.");
    }
  }

  // =========================
  // Handle QR Image Selection
  // =========================
  function handleFileChange(event) {
    const file = event.target.files[0];

    if (file) {
      setSelectedFile(file);

      // Create preview image
      setPreview(URL.createObjectURL(file));
    }
  }

  // =========================
  // Scan QR Code
  // =========================
  async function handleQRScan() {
    // Check if a file is selected
    if (!selectedFile) {
      alert("Please select a QR image.");
      return;
    }

    try {
      setLoading(true);

      // Create form data to send image
      const formData = new FormData();

      formData.append("qr_image", selectedFile);

      // Backend endpoint
      // (Will update after Diksha merges)
      const response = await fetch(
        "http://127.0.0.1:5000/predict_qr",
        {
          method: "POST",
          body: formData,
        }
      );

      const data = await response.json();

      setLoading(false);

      console.log(data);

      // Save prediction
      setResult(data);
    } catch (error) {
      setLoading(false);

      console.error(error);

      alert("QR Scan Failed");
    }
  }

  return (
    <div className="container">
      {/* ========================= */}
      {/* Project Heading */}
      {/* ========================= */}
      <h1 className="title">
        🛡️ AI Phishing & Malicious URL Detector
      </h1>

      <p>Detect phishing and malicious websites instantly.</p>

      {/* ========================= */}
      {/* URL Input */}
      {/* ========================= */}
      <input
        type="text"
        placeholder="Paste website URL here..."
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />

      {/* URL Scan Button */}
      <button onClick={handleScan} disabled={loading}>
        {loading ? (
          <>
            <span className="spinner"></span>
            Scanning...
          </>
        ) : (
          "Scan URL"
        )}
      </button>

      <hr style={{ margin: "35px 0" }} />

      {/* ========================= */}
      {/* QR Upload Section */}
      {/* ========================= */}
      <div className="qr-section">
        <h2>OR</h2>

        <div className="qr-upload">
          <h3>📷 Upload QR Code</h3>

          <input
            type="file"
            accept="image/*"
            onChange={handleFileChange}
          />

          {/* Display selected file */}
          {selectedFile && (
            <>
              <p className="selected-file">
                ✅ {selectedFile.name}
              </p>

              {/* QR Preview */}
              {preview && (
                <img
                  src={preview}
                  alt="QR Preview"
                  className="preview-img"
                />
              )}
            </>
          )}
        </div>

        {/* QR Scan Button */}
        <button
          className="scan-btn"
          onClick={handleQRScan}
          disabled={loading}
        >
          {loading ? "Scanning QR..." : "Scan QR Code"}
        </button>
      </div>

      <hr style={{ margin: "35px 0" }} />

      {/* ========================= */}
      {/* Prediction Result */}
      {/* ========================= */}
      {result && (
        <div className="result-card">
          <h2 style={{ fontSize: "38px" }}>
            Verdict:{" "}
            <span
              style={{
                color:
                  result.verdict === "LEGITIMATE"
                    ? "lightgreen"
                    : "red",
                fontWeight: "bold",
              }}
            >
              {result.verdict}
            </span>
          </h2>

          <p>Risk Score: {result.risk_score}%</p>

          {/* Probability Bars */}
          <div className="probability">
            <p>Legitimate Probability</p>

            <div className="bar">
              <div
                className="green"
                style={{
                  width: `${result.final_legitimate_prob}%`,
                }}
              >
                {result.final_legitimate_prob}%
              </div>
            </div>

            <p>Phishing Probability</p>

            <div className="bar">
              <div
                className="red"
                style={{
                  width: `${result.final_phishing_prob}%`,
                }}
              >
                {result.final_phishing_prob}%
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================= */}
      {/* Scan History */}
      {/* ========================= */}
      {history.length > 0 && (
        <div className="history-card">
          <h2>Recent Scans</h2>

          {history.map((item, index) => (
            <div key={index} className="history-item">
              <span>
                {item.verdict === "LEGITIMATE" ? "🟢" : "🔴"}
              </span>

              <span>{item.url}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default App;