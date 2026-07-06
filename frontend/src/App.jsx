import { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");

  async function handleScan() {
    if (!url.trim()) {
      alert("Please enter a URL");
      return;
    }

    try {
      const response = await fetch("http://localhost:5000/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: url,
        }),
      });

      const data = await response.json();

      console.log("Prediction Result:", data);

      alert(JSON.stringify(data, null, 2));
    } catch (error) {
      console.error("Error:", error);
      alert("Could not connect to the backend.");
    }
  }

  return (
    <div className="container">
      <h1 className="title">
        🛡️ AI Phishing & Malicious URL Detector
      </h1>

      <p>Detect phishing and malicious websites instantly.</p>

      <input
        type="text"
        placeholder="Paste website URL here..."
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />

      <button onClick={handleScan}>
        Scan URL
      </button>
    </div>
  );
}

export default App;