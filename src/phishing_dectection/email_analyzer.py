from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import re

class PhishingDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer()
        self.model = LogisticRegression()
        # Load pre-trained model
        
    def extract_urls(self, text):
        return re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)

    def is_phishing(self, email_body):
        urls = self.extract_urls(email_body)
        if any(url in PHISHING_BLACKLIST for url in urls):
            return True
        features = self.vectorizer.transform([email_body])
        return self.model.predict(features)[0] == 1