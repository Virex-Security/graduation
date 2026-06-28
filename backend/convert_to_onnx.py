import os
import sys
import time
import joblib
import logging
import traceback
from pathlib import Path
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings("ignore", category=UserWarning)

try:
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType, StringTensorType
except ImportError as e:
    print(f"Error importing skl2onnx: {e}. Please ensure it is installed.")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def find_project_root(current_path: Path) -> Path:
    """Finds the project root by looking for 'backend' or 'data' directories."""
    for parent in [current_path] + list(current_path.parents):
        if (parent / "backend").is_dir() or (parent / "data").is_dir():
            return parent
    return current_path

def find_data_dir(project_root: Path) -> Path:
    """Finds the data directory, prioritizing backend/data then data."""
    backend_data = project_root / "backend" / "data"
    if backend_data.is_dir():
        return backend_data
    root_data = project_root / "data"
    if root_data.is_dir():
        return root_data
    return project_root / "data"

def find_file(directory: Path, candidates: list) -> Path:
    """Searches for a file matching any of the candidate names."""
    for candidate in candidates:
        filepath = directory / candidate
        if filepath.exists():
            return filepath
    return None

def main():
    try:
        # 1. Detect project root
        current_script_path = Path(__file__).resolve().parent
        project_root = find_project_root(current_script_path)
        logger.info(f"Detected project root: {project_root}")
        
        # 2. Locate data directory
        data_dir = find_data_dir(project_root)
        logger.info(f"Detected data directory: {data_dir}")
        
        if not data_dir.exists():
            logger.error(f"Data directory could not be found at: {data_dir}")
            sys.exit(1)
            
        # 3. Detect model file
        model_candidates = ["model.pkl", "model_pipeline.pkl", "random_forest.pkl"]
        model_path = find_file(data_dir, model_candidates)
        
        # 4. Detect vectorizer file
        vec_candidates = ["vectorizer.pkl", "tfidf.pkl", "tfidf_vectorizer.pkl"]
        vec_path = find_file(data_dir, vec_candidates)
        
        # 5. Verify existence
        missing = []
        if not model_path:
            missing.append(f"Model file (searched for: {', '.join(model_candidates)} in {data_dir})")
        if not vec_path:
            missing.append(f"Vectorizer file (searched for: {', '.join(vec_candidates)} in {data_dir})")
            
        if missing:
            for m in missing:
                logger.error(f"Missing required file: {m}")
            sys.exit(1)
            
        logger.info(f"Detected model path: {model_path}")
        logger.info(f"Detected vectorizer path: {vec_path}")
        
        # 5b. Verify loadability
        logger.info("Verifying model loadability...")
        try:
            model = joblib.load(str(model_path))
            logger.info("Model loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load model from {model_path}. Error: {e}")
            logger.error(traceback.format_exc())
            sys.exit(1)
            
        logger.info("Verifying vectorizer loadability...")
        try:
            vectorizer = joblib.load(str(vec_path))
            logger.info("Vectorizer loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load vectorizer from {vec_path}. Error: {e}")
            logger.error(traceback.format_exc())
            sys.exit(1)
            
        # Determine number of features for FloatTensorType
        num_features = getattr(vectorizer, 'max_features', None)
        if num_features is None and hasattr(vectorizer, 'vocabulary_'):
            num_features = len(vectorizer.vocabulary_)
        if num_features is None and hasattr(vectorizer, 'get_feature_names_out'):
            num_features = len(vectorizer.get_feature_names_out())
            
        if num_features is None:
            logger.warning("Could not automatically determine number of features from vectorizer. Defaulting to 1000.")
            num_features = 1000
            
        # Determine initial type based on model type (pipeline vs raw model)
        from sklearn.pipeline import Pipeline
        if isinstance(model, Pipeline):
            initial_type = [('text_input', StringTensorType([None, 1]))]
            options = {id(model): {'zipmap': True}}
            logger.info("Detected Pipeline model. Using StringTensorType input.")
        else:
            initial_type = [('float_input', FloatTensorType([None, num_features]))]
            options = {id(model): {'zipmap': False}}
            logger.info(f"Detected standalone model. Using FloatTensorType input with {num_features} features.")
            
        # 8 & 9. Conversion process with exception handling
        onnx_filename = "rf_model.onnx"
        onnx_path = data_dir / onnx_filename
        
        logger.info("Starting ONNX conversion (this may take a moment)...")
        start_time = time.time()
        
        onx = convert_sklearn(model, initial_types=initial_type, options=options)
        
        conversion_time = time.time() - start_time
        logger.info(f"Conversion finished in {conversion_time:.2f} seconds.")
        
        # Save model
        with open(onnx_path, "wb") as f:
            f.write(onx.SerializeToString())
            
        size_mb = os.path.getsize(onnx_path) / (1024 * 1024)
        logger.info(f"ONNX model saved successfully to: {onnx_path}")
        logger.info(f"ONNX Model Size: {size_mb:.2f} MB")
        
    except Exception as e:
        logger.error(f"An unexpected error occurred during conversion: {e}")
        logger.error("Full traceback:")
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
