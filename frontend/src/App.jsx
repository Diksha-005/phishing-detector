import { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  function handleScan() {
  alert("Scanning: " + url);
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
  <p>You entered: {url}</p>
</div>
);
}

export default App;