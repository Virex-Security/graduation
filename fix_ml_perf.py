#!/usr/bin/env python
import re

# Read the file
with open('templates/ml_performance.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the escaped quotes in fetch URLs
#  Replace \"/api with "/api 
content = content.replace('\\\"/api', '\"/api')

# Write back
with open('templates/ml_performance.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed ml_performance.html - removed escaped quotes from fetch URLs")
