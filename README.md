# 🛡️ PhishNet – AI-Powered Phishing Link Detector 

PhishNet is a smart and lightweight Chrome extension designed to detect phishing links using cutting-edge AI technology. With a blend of GPT-based analysis, RAG hallucination detection, VirusTotal scanning, and domain intelligence, PhishNet protects users in real-time while browsing the web.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)](https://www.linkedin.com/in/padmanathan-c-070251316/)



---

## 🚀 Features

- 🔍 **Real-Time Link Analysis**  
  Instantly scans links on any webpage using GPT-powered backend.

- 🧠 **GPT + RAG Framework**  
  Uses Retrieval-Augmented Generation (RAG) to detect hallucinations in suspicious content.

- 🦠 **VirusTotal Integration**  
  Cross-checks URLs against the VirusTotal database for known threats.

- 🌐 **WHOIS & Domain Intelligence**  
  Analyzes domain age, registrar, and WHOIS data for legitimacy.

- 📉 **Risk Score System**  
  Assigns a risk level (Low, Medium, High) based on combined signals.

- 🚫 **Phishing Alert Popup**  
  Shows a red warning popup near links if flagged as dangerous.

---

## 🛠️ Tech Stack

- **Frontend**: Chrome Extension (HTML, CSS, JavaScript)
- **Backend**: FastAPI (Python)
- **AI Engine**: GPT-4 + RAG
- **APIs Used**:
  - VirusTotal
  - WHOIS XML API
  - OpenAI API

---

## 📦 Project Structure

PhishNet/
├── background.js
├── content.js
├── popup.html
├── popup.js
├── popup.css
├── blocked.html
├── manifest.json
└── backend/
├── main.py
└── detection_logic/
├── gpt_rag_checker.py
├── heuristics.py
└── virustotal_api.py

---

## 🧪 How It Works

1. **User visits a webpage**
2. **PhishNet scans all links in real time**
3. **Suspicious links are sent to the backend**
4. **RAG + GPT evaluates the context**
5. **If risk is high, a warning popup is shown near the link**

---

## 🚀 Getting Started (Developer)

1. Clone the repo:
   ```bash
   git clone https://github.com/yourusername/PhishNet.git
   cd PhishNet

2. Set up the FastAPI backend:
     cd backend
pip install -r requirements.txt
uvicorn main:app --reload

3. Load Chrome Extension:
Go to chrome://extensions/

Enable Developer Mode

Click Load Unpacked → Select the PhishNet folder

🛠️ Setup
> ⚠️ **Important:** This project does not include an OpenAI API key.  
> You must [get your own API key](https://platform.openai.com/) and add it in your local `.env` file.
> Use your Own Virus Total API key and other keys used in the code.


🧠 Future Plans
Feedback loop for user-reported false positives

Browser compatibility (Firefox, Edge)

Integration with enterprise dashboards

🤝 Contributing
Contributions, issues and feature requests are welcome!
Open a pull request or file an issue.

📄 License
This project is licensed under the MIT License.

🙏 Acknowledgements
OpenAI for GPT

VirusTotal for security data

WHOIS XML API for domain intelligence

👉Team  Members :

🗣️A huge shout out to the team mates who made it real!!!


padmanathan C - https://github.com/pc3604padma
Oviya B - https://github.com/Oviya-Babu
Achika Bala B B -https://github.com/AchikaBalabb
Subashri A - https://github.com/SUBA04116




