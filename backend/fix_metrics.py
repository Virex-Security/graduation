import json
import os

d = json.load(open('model_audit_results.json'))
lines = []
for k, v in d['default_metrics'].items():
    lines.append(f"- **{k}**: Precision: {v['precision']:.2f} | Recall: {v['recall']:.2f} | F1: {v['f1']:.2f} | Support: {v['support']}")

with open('models/evaluation/model_evaluation_report.md', 'w') as f:
    f.write("\n".join(lines))

print("Fixed!")
