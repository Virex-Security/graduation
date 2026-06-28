import os
import time
import joblib
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=UserWarning)

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import StringTensorType

PROJECT_ROOT = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "data"
MODEL_PATH = DATA_DIR / "model_pipeline.pkl"
ONNX_PATH = DATA_DIR / "model.onnx"

def main():
    if not MODEL_PATH.exists():
        print(f"Error: Could not find {MODEL_PATH}")
        return
        
    print(f"Loading joblib pipeline from {MODEL_PATH}...")
    pipeline = joblib.load(str(MODEL_PATH))
    
    print("Converting to ONNX (this may take a moment)...")
    t0 = time.time()
    
    initial_type = [('text_input', StringTensorType([None, 1]))]
    options = {id(pipeline): {'zipmap': True}}
    
    onx = convert_sklearn(pipeline, initial_types=initial_type, options=options)
    
    print(f"Conversion finished in {time.time()-t0:.2f}s")
    
    with open(ONNX_PATH, "wb") as f:
        f.write(onx.SerializeToString())
        
    print(f"ONNX model saved successfully to {ONNX_PATH}!")
    size_mb = os.path.getsize(ONNX_PATH) / (1024*1024)
    print(f"ONNX Model Size: {size_mb:.2f} MB")

if __name__ == "__main__":
    main()
