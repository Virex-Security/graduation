# ONNX Conversion Report

## 1. Conversion Details
- **Source Model**: LightGBM Classifier
- **Tooling**: `onnxmltools`
- **Target Opset**: 14
- **Conversion Duration**: 17.88 seconds

## 2. Validation Results (ONNX Runtime)
- **Input Tensor**: `input` | Shape: `[None, 5050]`
- **Output Tensors**: `label` (Shape: `[1]`) / `probabilities` (Shape: `[]`)
- **Status**: Loaded successfully in `InferenceSession`.

## 3. Prediction Consistency
Evaluated over 500 random samples from `test.csv`.
- **Prediction Agreement**: 100.00%
- **Average Prob Difference**: 7.73918629e-09
- **Max Prob Difference**: 2.22704204e-07

## 4. File Sizes
- **Pickle Model**: 3.58 MB
- **ONNX Model**: 2.03 MB

## 5. Production Readiness
The ONNX graph faithfully recreates the decision paths of the LightGBM model. Memory consumption is significantly reduced, and inference accuracy remains identical. The artifact is ready for high-speed deployment in the `inference.py` engine.
