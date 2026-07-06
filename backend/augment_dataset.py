import pandas as pd
import numpy as np
import random
import urllib.parse
import html
import base64
import json
import uuid
import hashlib

def url_encode(text):
    return urllib.parse.quote(text)

def double_url_encode(text):
    return urllib.parse.quote(urllib.parse.quote(text))

def unicode_escape(text):
    return ''.join(f'\\u{ord(c):04x}' for c in text)

def html_entity_encode(text):
    return html.escape(text)

def base64_encode(text):
    return base64.b64encode(text.encode()).decode()

def mix_case(text):
    return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in text)

def random_spaces(text):
    return text.replace(' ', ' ' * random.randint(2, 4))

def add_inline_comments(text):
    return text.replace(' ', '/**/')

def augment_attack(payload):
    # Apply a random augmentation
    aug_type = random.choice([
        url_encode, double_url_encode, unicode_escape, 
        html_entity_encode, base64_encode, mix_case, 
        random_spaces, add_inline_comments
    ])
    try:
        return aug_type(str(payload))
    except:
        return payload

def generate_benign_json():
    keys = ["id", "user", "email", "status", "role", "timestamp", "data", "token", "session"]
    payload = {random.choice(keys): random.randint(1, 10000), random.choice(keys): str(uuid.uuid4())}
    return json.dumps(payload)

def generate_benign_xml():
    return f'<?xml version="1.0"?><data><user>{uuid.uuid4().hex[:8]}</user><id>{random.randint(1, 100)}</id></data>'

def generate_benign_graphql():
    return f'{{"query": "query {{ user(id: \\"{random.randint(1, 1000)}\\") {{ name email }} }}"}}'

def generate_benign_jwt():
    header = base64.b64encode(b'{"alg":"HS256","typ":"JWT"}').decode()
    payload = base64.b64encode(f'{{"sub":"1234567890","name":"John Doe","iat":1516239022}}'.encode()).decode()
    signature = base64.b64encode(os.urandom(32)).decode()
    return f"Authorization: Bearer {header}.{payload}.{signature}"

def generate_benign_rest():
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    endpoints = ["/api/v1/users", "/api/data", "/api/config", "/api/auth/login", "/api/cart/checkout"]
    return f"{random.choice(methods)} {random.choice(endpoints)}?id={random.randint(1,100)} HTTP/1.1"

import os
def main():
    print("Loading datasets...")
    train = pd.read_csv('data/train.csv')
    val = pd.read_csv('data/validation.csv')
    test = pd.read_csv('data/test.csv')
    
    # Calculate current stats for reports
    stats_before = train['label'].value_counts().to_dict()
    
    # Phase 2 & Phase 3 & Phase 4: Augmentation
    new_train_rows = []
    
    # Expand Normal Traffic
    print("Generating benign traffic...")
    for _ in range(5000): new_train_rows.append({'payload': generate_benign_json(), 'label': 'normal'})
    for _ in range(5000): new_train_rows.append({'payload': generate_benign_xml(), 'label': 'normal'})
    for _ in range(3000): new_train_rows.append({'payload': generate_benign_graphql(), 'label': 'normal'})
    for _ in range(5000): new_train_rows.append({'payload': generate_benign_jwt(), 'label': 'normal'})
    for _ in range(5000): new_train_rows.append({'payload': generate_benign_rest(), 'label': 'normal'})
    
    # Expand Attack Traffic & Balance Minority Classes
    print("Augmenting attack traffic...")
    minority_classes = ['log4shell', 'ssti', 'xxe', 'ssrf', 'command_injection']
    
    for cls in minority_classes:
        subset = train[train['label'] == cls]['payload'].dropna().tolist()
        if not subset: continue
        # We want to add ~15000 augmented samples to minority classes
        for _ in range(15000):
            base_payload = random.choice(subset)
            aug_payload = augment_attack(base_payload)
            new_train_rows.append({'payload': aug_payload, 'label': cls})
            
    # For major classes (sqli, xss, path_traversal), just add 5000 variations
    for cls in ['sqli', 'xss', 'path_traversal']:
        subset = train[train['label'] == cls]['payload'].dropna().tolist()
        if not subset: continue
        for _ in range(5000):
            base_payload = random.choice(subset)
            aug_payload = augment_attack(base_payload)
            new_train_rows.append({'payload': aug_payload, 'label': cls})
            
    # Combine
    print("Merging...")
    new_train_df = pd.DataFrame(new_train_rows)
    augmented_train = pd.concat([train, new_train_df], ignore_index=True)
    
    # Remove duplicates
    augmented_train.drop_duplicates(subset=['payload'], inplace=True)
    
    # Validate leakage
    print("Validating leakage...")
    val_hashes = set(val['payload'].apply(lambda x: hash(str(x))))
    test_hashes = set(test['payload'].apply(lambda x: hash(str(x))))
    
    def is_leaked(payload):
        h = hash(str(payload))
        return h in val_hashes or h in test_hashes
        
    augmented_train = augmented_train[~augmented_train['payload'].apply(is_leaked)]
    
    stats_after = augmented_train['label'].value_counts().to_dict()
    
    augmented_train.to_csv('data/train_v4.csv', index=False)
    
    print("Stats Before:", stats_before)
    print("Stats After:", stats_after)

if __name__ == "__main__":
    main()
