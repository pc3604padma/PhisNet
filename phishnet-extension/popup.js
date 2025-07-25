document.addEventListener("DOMContentLoaded", () => {
  const scanButton = document.getElementById("scan-btn");
  const resultBox = document.getElementById("result");

  scanButton.addEventListener("click", () => {
    resultBox.className = "loading";
    resultBox.textContent = "⏳ Scanning current tab URL...";

    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      const currentUrl = tabs[0]?.url;
      if (!currentUrl || !/^https?:\/\//.test(currentUrl)) {
        resultBox.className = "malicious";
        resultBox.textContent = "❌ Invalid or unsupported URL.";
        return;
      }

      fetch("http://127.0.0.1:8000/analyze-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: currentUrl })
      })
      .then(response => {
        if (!response.ok) {
          throw new Error(`Backend error: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        displayScanResult(data);
      })
      .catch(error => {
        resultBox.className = "malicious";
        resultBox.textContent = "⚠ Scan failed: " + error.message;
      });
    });
  });

  function displayScanResult(data) {
    const {
      url,
      risk_score = "N/A",
      domain_age_days = "N/A",
      ai_written = "N/A",
      message = "No message",
      malicious
    } = data;

    let statusClass = "safe";
    if (malicious) {
      statusClass = "malicious";
    } else if (risk_score >= 30) {
      statusClass = "suspicious";
    }

    resultBox.className = statusClass;
    resultBox.innerHTML = `
      🔗 URL: ${url}<br><br>
      🧠 Risk Score: ${risk_score}/100<br><br>
      📅 Domain Age: ${domain_age_days} days<br><br>
      ✍️ AI Detection: ${ai_written}<br><br>
      🚨 Verdict: ${message}
    `;
  }
});
