import { useState } from "react";
import "./App.css";

function App() {

  // Stores the URL entered by the user
  const [url, setUrl] = useState("");

  // Stores the prediction received from the backend
  const [result, setResult] = useState(null);

  // Controls the loading spinner while scanning
  const [loading, setLoading] = useState(false);

  // Stores the last 5 scanned URLs
  const [history, setHistory] = useState([]);

  // Function called when user clicks "Scan URL"
  async function handleScan() {

    // Prevent scanning if input is empty
    if (!url.trim()) {
      alert("Please enter a URL");
      return;
    }

    try {

      // Show loading spinner
      setLoading(true);

      // Send URL to Flask backend
      const response = await fetch("http://127.0.0.1:5000/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },

        // Convert URL into JSON format
        body: JSON.stringify({ url }),
      });

      // Receive prediction from backend
      const data = await response.json();

      // Stop loading spinner
      setLoading(false);

      console.log("Prediction Result:", data);

      // Store prediction result
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

      // Stop loading if any error occurs
      setLoading(false);

      console.error(error);

      alert("Could not connect to backend.");
    }
  }

  return (
    <div className="container">

      {/* Project Heading */}
      <h1 className="title">
        🛡️ AI Phishing & Malicious URL Detector
      </h1>

      <p>Detect phishing and malicious websites instantly.</p>

      {/* URL Input Field */}
      <input
        type="text"
        placeholder="Paste website URL here..."
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />

      {/* Scan Button */}
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

      {/* Display Prediction Result */}
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

      {/* Display Last 5 Scanned URLs */}
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
