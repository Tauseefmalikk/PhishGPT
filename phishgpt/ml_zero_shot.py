from transformers import pipeline

classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

def classify_email_zero_shot(text):
    labels = ["Phishing", "Legitimate", "Suspicious"]
    result = classifier(text, labels)
    top_label = result["labels"][0]
    score = result["scores"][0]
    return top_label, score
