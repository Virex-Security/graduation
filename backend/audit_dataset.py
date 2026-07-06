import pandas as pd
import numpy as np
import json
import os

def run_audit():
    data_dir = 'data'
    train_path = os.path.join(data_dir, 'train.csv')
    val_path = os.path.join(data_dir, 'validation.csv')
    test_path = os.path.join(data_dir, 'test.csv')

    df_train = pd.read_csv(train_path) if os.path.exists(train_path) else pd.DataFrame()
    df_val = pd.read_csv(val_path) if os.path.exists(val_path) else pd.DataFrame()
    df_test = pd.read_csv(test_path) if os.path.exists(test_path) else pd.DataFrame()
    
    df_train['split'] = 'train'
    df_val['split'] = 'val'
    df_test['split'] = 'test'

    all_data = pd.concat([df_train, df_val, df_test], ignore_index=True)
    all_data['payload'] = all_data['payload'].astype(str)
    
    # 1. Class distribution & 8. Compare splits
    dist = {
        'train': df_train['label'].value_counts().to_dict() if not df_train.empty else {},
        'val': df_val['label'].value_counts().to_dict() if not df_val.empty else {},
        'test': df_test['label'].value_counts().to_dict() if not df_test.empty else {},
        'total': all_data['label'].value_counts().to_dict()
    }
    
    # 2. Duplicate samples
    exact_duplicates = all_data.duplicated(subset=['payload', 'label']).sum()
    
    # 3. Label noise & 6. Inconsistent labels
    # Find payloads that have multiple different labels
    payload_labels = all_data.groupby('payload')['label'].nunique()
    inconsistent_payloads = payload_labels[payload_labels > 1].index.tolist()
    
    inconsistent_details = []
    sqli_normal_overlap = 0
    for p in inconsistent_payloads:
        labels = all_data[all_data['payload'] == p]['label'].unique().tolist()
        inconsistent_details.append({"payload_sample": p[:50], "labels": labels})
        if 'normal' in labels and 'sqli' in labels:
            sqli_normal_overlap += 1

    # 4. Overlap specifically between Normal and SQLi
    # Even if not exact duplicates, maybe very similar? We'll track exact overlap via inconsistent labels.
    
    # 5. Malformed payloads (empty, very short, extremely long)
    all_data['length'] = all_data['payload'].str.len()
    malformed_empty = (all_data['length'] == 0).sum()
    malformed_short = (all_data['length'] < 3).sum()
    malformed_long = (all_data['length'] > 10000).sum()

    # Write summary
    report = {
        "distributions": dist,
        "exact_duplicates_across_all_dataset": int(exact_duplicates),
        "inconsistent_labels_count": len(inconsistent_payloads),
        "sqli_normal_exact_overlap_count": sqli_normal_overlap,
        "malformed": {
            "empty": int(malformed_empty),
            "under_3_chars": int(malformed_short),
            "over_10000_chars": int(malformed_long)
        },
        "sample_inconsistencies": inconsistent_details[:10]
    }
    
    with open('audit_results.json', 'w') as f:
        json.dump(report, f, indent=2)

if __name__ == "__main__":
    run_audit()
