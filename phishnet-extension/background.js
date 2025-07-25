chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // Proceed only when the tab is fully loaded and uses HTTP/HTTPS
    if (changeInfo.status === "complete" && /^https?:\/\//.test(tab.url)) {
      try {
        const backendUrl = "http://localhost:8000/evaluate-urls"; // Updated endpoint
        const urlToCheck = tab.url;
  
        // Prepare payload
        const payload = {
          test_data: [
            {
              url: urlToCheck,
              label: false // placeholder label, not needed for detection
            }
          ]
        };
  
        // Send URL to backend for phishing analysis
        const response = await fetch(backendUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
  
        if (!response.ok) {
          throw new Error(`Server responded with status ${response.status}`);
        }
  
        const data = await response.json();
        const result = data.results?.[0];
  
        if (result?.malicious) {
          console.warn("🚨 Malicious site detected:", urlToCheck);
  
          const reason = `
            🔴 Risk Score: ${result.risk_score || "?"}/100
            🤖 GPT Verdict: ${result.gpt_analysis || "Phishing risk"}
            📆 Domain Age: ${result.domain_age_days || "N/A"} days
            ✍️ AI-Written Content: ${result.ai_written || "Not analyzed"}
            🔍 Keywords: ${result.content_heuristics?.keywords_found?.join(", ") || "None"}
          `.trim();
  
          // Notify content script to block the site
          chrome.tabs.sendMessage(tabId, {
            action: "block_site",
            url: urlToCheck,
            reason: reason
          });
  
          // Show desktop notification
          chrome.notifications.create({
            type: "basic",
            iconUrl: "icon.png",
            title: "🚨 Phishing Alert",
            message: `Warning: The site "${urlToCheck}" is potentially malicious.`,
            contextMessage: reason,
            priority: 2
          });
        } else {
          console.log("✅ Safe site:", urlToCheck);
        }
      } catch (err) {
        console.error("❌ Error during phishing check:", err.message);
      }
    }
  });
  