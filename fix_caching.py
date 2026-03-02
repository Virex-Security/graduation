#!/usr/bin/env python
"""Add metrics caching to prevent wild fluctuations on refresh"""

import re

# Read the file
with open('dashboard.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the return statement to cache metrics
old_return = '''        # sort descending so strongest indicators appear first
        attack_features.sort(key=lambda x: x['importance'], reverse=True)
        return {'''

new_return = '''        # sort descending so strongest indicators appear first
        attack_features.sort(key=lambda x: x['importance'], reverse=True)
        metrics = {'''

content = content.replace(old_return, new_return)

# Add caching logic before the return
old_end = '''            "live_data_active": live_data_active,
        }
    def calculate_security_score'''

new_end = '''            "live_data_active": live_data_active,
        }
        # Cache the metrics to prevent wild fluctuations on refresh
        with self.ml_metrics_lock:
            self.last_ml_metrics = metrics
        return metrics
    def calculate_security_score'''

content = content.replace(old_end, new_end)

# Write back
with open('dashboard.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ Added metrics caching to prevent wild fluctuations")
