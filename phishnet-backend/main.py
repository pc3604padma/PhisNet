from fastapi import FastAPI
from pydantic import BaseModel
import requests
import os
import time
import openai
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
from typing import List
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from transformers import BertTokenizer, BertForSequenceClassification
import torch
from sentence_transformers import SentenceTransformer, util

# Load environment variables
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")

openai.api_key = OPENAI_API_KEY

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

class TestItem(BaseModel):
    url: str
    label: bool

class EvaluationRequest(BaseModel):
    test_data: List[TestItem]

# Load AI models once
semantic_model = SentenceTransformer('all-MiniLM-L6-v2')
tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
bert_model = BertForSequenceClassification.from_pretrained('bert-base-uncased', num_labels=2)
bert_model.eval()

# --- Helper Functions ---

def retrieve_relevant_data(query, documents):
    embeddings = semantic_model.encode(documents, convert_to_tensor=True)
    query_embedding = semantic_model.encode(query, convert_to_tensor=True)
    similarities = util.pytorch_cos_sim(query_embedding, embeddings)[0]
    top_k = 5
    top_results = torch.topk(similarities, k=top_k)
    return [documents[idx] for idx in top_results[1]]

def fetch_page_html(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36"
    }
    try:
        response = requests.get(url, headers=headers, timeout=8)
        if response.status_code == 200:
            return response.text
        else:
            return ""
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return ""

def get_domain_age(domain):
    try:
        response = requests.get(
            "https://www.whoisxmlapi.com/whoisserver/WhoisService",
            params={
                "apiKey": WHOIS_API_KEY,
                "domainName": domain,
                "outputFormat": "JSON"
            }, timeout=8
        )
        data = response.json()
        created = data.get("WhoisRecord", {}).get("createdDate")
        if created:
            created_dt = datetime.strptime(created, "%Y-%m-%dT%H:%M:%S%z")
            return (datetime.now(created_dt.tzinfo) - created_dt).days
        else:
            return None
    except Exception as e:
        print(f"WHOIS error: {e}")
        return None

def crawl_and_analyze(html):
    try:
        soup = BeautifulSoup(html, "html.parser")
        has_form = bool(soup.find("form"))
        keywords = ["password", "verify", "login"]
        found_keywords = [kw for kw in keywords if kw in html.lower()]
        suspicious_images = [
            img.get("src", "") for img in soup.find_all("img")
            if any(b in img.get("src", "").lower() for b in ["paypal", "bank", "login"])
        ]
        return {
            "has_form": has_form,
            "keywords_found": found_keywords,
            "suspicious_images": suspicious_images
        }
    except Exception as e:
        print(f"HTML parse error: {e}")
        return {"error": str(e)}

def detect_ai_text(content):
    if not OPENAI_API_KEY:
        return "OpenAI API key missing."

    if not content:
        return "Unable to analyze"

    prompt = f"Does the following content appear AI-generated? Give a short explanation.\n\n{content[:2000]}"
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=150,
            temperature=0.3
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"OpenAI error: {e}")
        return f"❌ AI detect error: {str(e)}"

def classify_url_with_bert(url):
    try:
        inputs = tokenizer(url, return_tensors="pt", truncation=True, padding=True, max_length=512)
        with torch.no_grad():
            outputs = bert_model(**inputs)
        logits = outputs.logits
        predicted_class = torch.argmax(logits, dim=-1).item()
        return "Phishing" if predicted_class == 1 else "Safe"
    except Exception as e:
        print(f"BERT classification error: {e}")
        return "Safe"

def calculate_risk_score(data):
    score = 0
    explanation = []

    if data.get("domain_age_days") is not None and data["domain_age_days"] < 30:
        score += 25
        explanation.append(f"The domain is {data['domain_age_days']} days old.")
    if data.get("content_heuristics", {}).get("has_form"):
        score += 20
        explanation.append("Suspicious form detected.")
    if data.get("content_heuristics", {}).get("keywords_found"):
        score += 15
        explanation.append(f"Keywords found: {', '.join(data['content_heuristics']['keywords_found'])}.")
    if data.get("content_heuristics", {}).get("suspicious_images"):
        score += 10
        explanation.append("Suspicious images detected.")
    if "ai-generated" in (data.get("ai_written", "").lower()):
        score += 20
        explanation.append("AI-generated content detected.")
    if "phishing" in (data.get("bert_classification", "").lower()):
        score += 10
        explanation.append("BERT model flagged as phishing.")

    if score > 40:
        return min(score, 100), "⚠️ Suspicious Activity Detected!", explanation
    else:
        return min(score, 100), "✅ URL appears safe.", explanation

# --- Fast endpoint for Chrome Extension ---

@app.post("/analyze-url")
def analyze_url(req: URLRequest):
    url_to_scan = req.url
    parsed_domain = urlparse(url_to_scan).netloc

    html = fetch_page_html(url_to_scan)
    domain_age_days = get_domain_age(parsed_domain)
    heuristics = crawl_and_analyze(html)
    ai_written = detect_ai_text(html)
    bert_classification = classify_url_with_bert(url_to_scan)

    final_data = {
        "domain_age_days": domain_age_days,
        "content_heuristics": heuristics,
        "ai_written": ai_written,
        "bert_classification": bert_classification,
    }

    score, message, explanation = calculate_risk_score(final_data)

    return {
        "url": url_to_scan,
        "risk_score": score,
        "domain_age_days": domain_age_days,
        "ai_written": ai_written,
        "bert_classification": bert_classification,
        "message": message,
        "malicious": score > 60,
        "explanation": explanation
    }
