import pandas as pd
import re
import json

def audit_v4():
    df = pd.read_csv('data/train_v4.csv')
    df['payload'] = df['payload'].fillna('')
    
    total = len(df)
    
    stats = {}
    stats['total'] = total
    stats['class_distribution'] = df['label'].value_counts().to_dict()
    
    # Payload length
    df['length'] = df['payload'].str.len()
    stats['avg_payload_length'] = float(df['length'].mean())
    
    # Detect encodings / structures
    def count_matches(pattern):
        return int(df['payload'].str.contains(pattern, flags=re.IGNORECASE, regex=True).sum())
    
    stats['encoded_url'] = count_matches(r'%[0-9a-f]{2}')
    stats['encoded_unicode'] = count_matches(r'\\u[0-9a-f]{4}')
    stats['encoded_html'] = count_matches(r'&#?[a-z0-9]+;')
    stats['encoded_base64'] = count_matches(r'base64')
    
    stats['json'] = count_matches(r'\{.*"[\w]+"\s*:.*\}')
    stats['xml'] = count_matches(r'<\?xml|<[\w]+>.*</[\w]+>')
    stats['jwt'] = count_matches(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')
    stats['rest_api'] = count_matches(r'GET /api|POST /api|PUT /api|DELETE /api')
    
    with open('v4_audit_after.json', 'w') as f:
        json.dump(stats, f, indent=2)

if __name__ == "__main__":
    audit_v4()
