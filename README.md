# PhishGPT
# 🛡️ PhishGPT: AI-Powered Email Phishing Detection System

PhishGPT is a cutting-edge phishing detection system that automatically retrieves emails using the Gmail API, parses their content, and applies AI-powered models to detect phishing threats. It combines zero-shot classification with domain and URL reputation analysis to offer a robust, real-time email security solution. The interactive Streamlit dashboard allows users to monitor, analyze, and explain email threats intuitively.

---

## 🧠 Key Features

- **📥 Automated Email Retrieval**: Secure integration with Gmail API to fetch and parse emails in real time.
- **🕵️ Zero-Shot Phishing Detection**: Utilizes Hugging Face’s `mohitmisra/zeroshot-phishing-detector` for context-aware phishing classification.
- **🔗 URL & Domain Reputation Check**: Scans all URLs using VirusTotal or similar APIs to validate domain trustworthiness.
- **📊 Interactive Dashboard**: Built with Streamlit to visualize phishing emails, threat categories, and metadata.
- **🧠 Threat Explanation**: Optionally integrates with local LLMs (e.g., Mistral via Ollama) for simplified threat summaries.
- **🧪 Intelligent Parsing**: Extracts sender info, subject, links, and text from both HTML and plain-text emails.
- **🔐 OAuth2 Authentication**: Secure token-based login to access Gmail API without exposing credentials.

---

## 🚀 How It Works

1. **OAuth Authentication**  
   Logs into your Gmail account using secure OAuth2 and stores the access token.

2. **Email Parsing**  
   Automatically fetches unread emails, extracts subject, sender, body, and any URLs.

3. **Phishing Detection**  
   - Applies a zero-shot model to label emails as *phishing*, *benign*, or *suspicious*.
   - Checks links using VirusTotal or other domain reputation services.

4. **Dashboard Display**  
   Streamlit-based UI displays:
   - Email metadata
   - Prediction confidence
   - Threat summaries
   - URL/domain verdicts

5. **User Feedback Loop (Optional)**  
   Users can label misclassified emails to improve future predictions (future enhancement).

---


