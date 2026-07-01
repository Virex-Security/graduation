"""
backend/mlops/model_registry/__init__.py
=========================================
Virex Security — Model Registry Sub-Package

The model_registry/ directory stores versioned model artifacts:
    model_v1/
    ├── model.pkl
    ├── model.onnx
    ├── vectorizer.pkl
    ├── preprocessor.pkl
    ├── label_encoder.pkl
    ├── metrics.json
    ├── feature_importance.json
    ├── training_config.json
    ├── dataset_version.json
    └── training_timestamp.txt

current_model.json always points to the active production champion.
"""
