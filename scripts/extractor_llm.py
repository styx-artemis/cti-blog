# extractor_llm.py

import logging
import re
import torch
import fitz # PyMuPDF
import nltk
import requests
import pandas as pd
from nltk.tokenize import sent_tokenize
from dateutil import parser as date_parser
from transformers import BertTokenizer, BertForSequenceClassification
from huggingface_hub import snapshot_download

# ----------------------------------------------------------------------
# INITIAL SETUP
# ----------------------------------------------------------------------

# Setup logging
logging.basicConfig(level=logging.INFO)
nltk.download('punkt', quiet=True)

# ----------------------------------------------------------------------
# LOAD MODEL & DEVICE SETUP
# ----------------------------------------------------------------------

REPO_ID = "styx8114/scibert-threat-model"
MODEL_DIR_CACHE = "scibert_model_cache"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

try:
    logging.info(f"Downloading model from Hugging Face Hub: {REPO_ID}")
    model_path = snapshot_download(repo_id=REPO_ID, local_dir=MODEL_DIR_CACHE)
    
    TOKENIZER = BertTokenizer.from_pretrained(model_path)
    MODEL = BertForSequenceClassification.from_pretrained(model_path).to(DEVICE).eval()
    ID2LABEL = MODEL.config.id2label
    logging.info(f"✅ SciBERT loaded successfully on {DEVICE}")
except Exception as e:
    logging.error(f"❌ Failed to load model from Hugging Face: {e}")
    TOKENIZER, MODEL, ID2LABEL = None, None, None

# ----------------------------------------------------------------------
# LOAD MITRE ATT&CK DATA
# ----------------------------------------------------------------------

def load_mitre_data():
    """Fetches and loads the latest MITRE ATT&CK data from GitHub."""
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error(f"❌ MITRE data fetch error: {e}")
        return None

def parse_mitre(json_data):
    """Parses MITRE JSON to extract TTPs and malware relationships."""
    if not json_data or 'objects' not in json_data:
        return {}, set(), {}
    
    ttps = {}
    malware_set = set()
    malware_to_ttps = {}
    
    techniques = {
        obj['id']: (obj['external_references'][0]['external_id'], obj['name'])
        for obj in json_data['objects']
        if obj['type'] == 'attack-pattern' and obj.get('external_references')
    }
    
    malware_ids = {
        obj['id']: obj['name']
        for obj in json_data['objects']
        if obj['type'] == 'malware'
    }
    
    for obj in json_data['objects']:
        if obj['type'] == 'attack-pattern':
            ref = next((r.get('external_id') for r in obj['external_references']
                        if r.get('source_name') == 'mitre-attack'), None)
            if ref:
                ttps[ref] = obj['name']
        elif obj['type'] == 'malware':
            malware_set.add(obj['name'].lower())
        elif obj['type'] == 'relationship' and obj.get('relationship_type') == 'uses':
            source, target = obj.get('source_ref', ''), obj.get('target_ref', '')
            if source.startswith("malware--") and target in techniques:
                malware = malware_ids.get(source)
                ttp_id, ttp_name = techniques[target]
                if malware:
                    malware_to_ttps.setdefault(malware.lower(), []).append(f"{ttp_id} – {ttp_name}")
                    
    return ttps, malware_set, malware_to_ttps

MITRE_JSON = load_mitre_data()
MITRE_TTPS, MITRE_MALWARE_NAMES, MITRE_MALWARE_MAP = parse_mitre(MITRE_JSON)

# ----------------------------------------------------------------------
# PDF TEXT EXTRACTION
# ----------------------------------------------------------------------

def extract_text_from_stream(pdf_stream):
    """Extracts text from a PDF file stream using PyMuPDF."""
    try:
        pdf_stream.seek(0)
        with fitz.open(stream=pdf_stream.read(), filetype="pdf") as doc:
            return "\n".join([page.get_text() for page in doc])
    except Exception as e:
        logging.error(f"⚠️ PDF reading error: {e}")
        return ""

# ----------------------------------------------------------------------
# TTP EXTRACTION
# ----------------------------------------------------------------------

def extract_ttps_by_match(text):
    """Extracts TTPs by simple keyword matching."""
    lower = text.lower()
    return [{"id": k, "description": v} for k, v in MITRE_TTPS.items() if v.lower() in lower]

def extract_ttps_by_model(text, threshold=0.3):
    """Extracts TTPs using the fine-tuned SciBERT model."""
    if not all([MODEL, TOKENIZER, ID2LABEL]):
        return []
    
    inputs = TOKENIZER(text, truncation=True, max_length=512, padding=True, return_tensors="pt")
    inputs = {k: v.to(DEVICE) for k, v in inputs.items()}
    
    with torch.no_grad():
        logits = MODEL(**inputs).logits
        probs = torch.sigmoid(logits).squeeze()
    
    predicted = [ID2LABEL[i] for i in (probs > threshold).nonzero(as_tuple=True)[0].tolist()]
    return [{"id": tid, "description": MITRE_TTPS.get(tid, "Unknown")} for tid in predicted]

def extract_ttps_with_fallback(text):
    """Combines keyword and model-based TTP extraction."""
    found = extract_ttps_by_match(text)
    if found:
        return found
    return extract_ttps_by_model(text)

# ----------------------------------------------------------------------
# MALWARE EXTRACTION
# ----------------------------------------------------------------------

def extract_malware(text):
    """Extracts known malware names from text."""
    lower = text.lower()
    matched = {m for m in MITRE_MALWARE_NAMES if re.search(rf'\b{re.escape(m)}\b', lower)}
    
    return [{
        "name": m.title(),
        "ttps": MITRE_MALWARE_MAP.get(m, [])
    } for m in matched]

# ----------------------------------------------------------------------
# DATE & TIMELINE PROCESSING
# ----------------------------------------------------------------------

def extract_dates(text):
    """Finds potential date strings in text using regex."""
    date_patterns = [
        r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},\s+\d{4}\b',
        r'\b\d{4}-\d{2}-\d{2}\b',
        r'\b\d{1,2}/\d{1,2}/\d{2,4}\b',
        r'\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}\b',
    ]
    matches = set()
    for pat in date_patterns:
        matches.update(re.findall(pat, text))
    return sorted(matches)

def get_context(text, dates, window=2):
    """Finds sentences around a specific date for context."""
    sents = sent_tokenize(text)
    context = []
    for date in dates:
        for i, sent in enumerate(sents):
            if date in sent:
                start = max(0, i - window)
                end = min(len(sents), i + window + 1)
                context.append((date, " ".join(sents[start:end])))
    return context

def safe_parse(date_str):
    """Safely parses a date string, returning NaT on failure."""
    try:
        return date_parser.parse(date_str, fuzzy=True)
    except Exception:
        return pd.NaT

def build_timeline(text):
    """Builds a timeline of TTPs based on dates found in the text."""
    dates = extract_dates(text)
    contexts = get_context(text, dates)
    
    timeline = []
    for date, ctx in contexts:
        ttps = extract_ttps_with_fallback(ctx)
        if ttps:
            timeline.append({
                "timestamp": date,
                "TTPs": [t["id"] for t in ttps],
                "context": ctx
            })
    
    if not timeline:
        return pd.DataFrame()
        
    df = pd.DataFrame(timeline)
    df['timestamp'] = df['timestamp'].apply(safe_parse)
    return df.dropna(subset=["timestamp", "TTPs"])

# ----------------------------------------------------------------------
# MAIN ORCHESTRATION FUNCTION
# ----------------------------------------------------------------------

def analyze_report_data(file_stream):
    """Main function to analyze a PDF report and extract threat intelligence."""
    text = extract_text_from_stream(file_stream)
    if not text.strip():
        return {"error": "No text extracted from the PDF."}
    
    return {
        "report_ttps": extract_ttps_with_fallback(text),
        "malware": extract_malware(text),
        "timeline_df": build_timeline(text),
        "error": None
    }