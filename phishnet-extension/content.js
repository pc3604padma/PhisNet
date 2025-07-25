chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "block_site") {
      // Clear the current page
      document.head.innerHTML = "";
      document.body.innerHTML = "";
  
      // Create a full-screen warning container
      const warningContainer = document.createElement("div");
      warningContainer.style.cssText = `
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        height: 100vh;
        background-color: #1a1a1a;
        color: #ff4c4c;
        font-family: 'Segoe UI', sans-serif;
        padding: 30px;
        text-align: center;
      `;
  
      const warningTitle = document.createElement("h1");
      warningTitle.textContent = "🚫 WARNING: Malicious Website Detected";
  
      const urlInfo = document.createElement("p");
      urlInfo.style.fontSize = "18px";
      urlInfo.style.maxWidth = "80%";
      urlInfo.textContent = `The site you tried to visit: ${message.url}`;
  
      const reason = document.createElement("p");
      reason.style.marginTop = "10px";
      reason.style.fontWeight = "bold";
      reason.textContent = `Reason: ${message.reason}`;
  
      const footer = document.createElement("p");
      footer.style.marginTop = "20px";
      footer.textContent = "Access has been blocked by PhishNet for your protection.";
  
      const closeButton = document.createElement("button");
      closeButton.textContent = "Close Tab";
      closeButton.style.cssText = `
        margin-top: 30px;
        padding: 10px 20px;
        font-size: 16px;
        background-color: #ff4c4c;
        color: white;
        border: none;
        border-radius: 6px;
        cursor: pointer;
      `;
      closeButton.onclick = () => {
        window.close(); // Close the tab if it was opened in a new tab or window
      };
  
      // Optional: Add more details like Risk Score, Domain Age, and AI Detection in the warning
      const extraDetails = document.createElement("div");
      extraDetails.style.marginTop = "20px";
      extraDetails.style.fontSize = "16px";
      extraDetails.style.maxWidth = "80%";
      extraDetails.style.textAlign = "left";
  
      // Extracting more specific details from message.reason if available
      const riskScoreMatch = message.reason.match(/risk score (\d+\/\d+)/i);
      const domainAgeMatch = message.reason.match(/Domain Age: (\d+ days?)/i);
      const aiGeneratedText = message.reason.includes("AI-generated") ? "Yes" : "No";
      const keywordsFoundMatch = message.reason.match(/Keywords: (.+)/i);
  
      extraDetails.innerHTML = `
        <strong>🔗 URL:</strong> ${message.url} <br>
        <strong>🧠 Risk Score:</strong> ${riskScoreMatch ? riskScoreMatch[1] : "N/A"}<br>
        <strong>📅 Domain Age:</strong> ${domainAgeMatch ? domainAgeMatch[1] : "N/A"} <br>
        <strong>🧬 AI-Generated Text:</strong> ${aiGeneratedText}<br>
        <strong>🕵️ HTML Heuristics:</strong> ${keywordsFoundMatch ? keywordsFoundMatch[1] : "No suspicious keywords found"}<br>
      `;
  
      // Append all elements
      warningContainer.appendChild(warningTitle);
      warningContainer.appendChild(urlInfo);
      warningContainer.appendChild(reason);
      warningContainer.appendChild(extraDetails); // Appending additional details
      warningContainer.appendChild(footer);
      warningContainer.appendChild(closeButton);
  
      // Inject the warning screen
      document.body.appendChild(warningContainer);
    }
  });
  