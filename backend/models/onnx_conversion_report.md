# ONNX Conversion Report

## 1. Conversion Details
- **Source Model**: LightGBM Classifier
- **Tooling**: `onnxmltools`
- **Target Opset**: 14
- **Conversion Duration**: 6.57 seconds

## 2. Validation Results (ONNX Runtime)
- **Input Tensor**: `input` | Shape: `[None, 3052]`
- **Output Tensors**: `label` (Shape: `[1]`) / `probabilities` (Shape: `[]`)
- **Status**: Loaded successfully in `InferenceSession`.

## 3. Prediction Consistency
Evaluated over 500 random samples from `test.csv`.
- **Prediction Agreement**: 100.00%
- **Average Prob Difference**: 7.60128849e-09
- **Max Prob Difference**: 2.70667055e-07

## 4. File Sizes
- **Pickle Model**: 3.17 MB
- **ONNX Model**: 1.92 MB

## 5. Production Readiness
The ONNX graph faithfully recreates the decision paths of the LightGBM model. Memory consumption is significantly reduced, and inference accuracy remains identical. The artifact is ready for high-speed deployment in the `inference.py` engine.
