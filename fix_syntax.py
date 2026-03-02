#!/usr/bin/env python

# Read the file
with open('templates/ml_performance.html', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Fix lines with escaped quotes
for i, line in enumerate(lines):
    # Replace stray backslash characters before quotes
    if 'fetch(' in line and '\\"' in line:
        line = line.replace('\\"', '"')
        lines[i] = line

# Write back
with open('templates/ml_performance.html', 'w', encoding='utf-8') as f:
    f.writelines(lines)

print("Fixed! Removed invalid escape sequences")
