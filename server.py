from flask import Flask, request, jsonify
from flask_cors import CORS
import pefile, os, tempfile
import pandas as pd
import numpy as np
import joblib
import xgboost as xgb
from datetime import datetime
import warnings
import shap
import json
from typing import Dict, List, Tuple, Any
import hashlib
import time

# Import your feature extraction function
from feature_extraction import extract_features, is_pe_file

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

app = Flask(__name__)

# ================================
# FIXED CORS CONFIGURATION
# ================================
# Allow all origins including file:// protocol
CORS(app, 
     origins=["*"],  # Allow all origins
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "OPTIONS"])

# ================================
# ADD OPTIONS HANDLER FOR PREFLIGHT
# ================================
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify({'message': 'OK'})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response

# ================================
# FILE PATHS (Windows)
# ================================
BASE_PATH = r"D:\daily task files\tugas-tugas\pelajaran taiwan ntou\113\113-2\Ransomware project\web\Website"
ENSEMBLE_PATH = os.path.join(BASE_PATH, "ensemble_model.pkl")
SCALER_PATH = os.path.join(BASE_PATH, "feature_scaler.pkl")
FEATURE_COLUMNS_PATH = os.path.join(BASE_PATH, "feature_columns.pkl")
SHAP_EXPLAINER_PATH = os.path.join(BASE_PATH, "shap_explainer.pkl")
BACKGROUND_DATA_PATH = os.path.join(BASE_PATH, "background_data.pkl")

# ================================
# GLOBAL VARIABLES FOR SHAP
# ================================
shap_explainer = None
background_data = None
feature_names = None

# ================================
# LOAD MODELS AND PREPROCESSING
# ================================
print("[INFO] Loading models and preprocessing components...")

# Load the complete ensemble model
ensemble = joblib.load(ENSEMBLE_PATH)

# Load scaler
scaler = joblib.load(SCALER_PATH)

# Try to load feature columns, use fallback if not available
try:
    feature_columns = joblib.load(FEATURE_COLUMNS_PATH)
    feature_names = feature_columns
    print(f"[INFO] Loaded feature columns: {len(feature_columns)}")
except FileNotFoundError:
    print("[WARNING] feature_columns.pkl not found, using fallback feature order")
    feature_columns = None

print(f"[INFO] Loaded ensemble with estimators: {list(ensemble.named_estimators_.keys())}")

# ================================
# SHAP EXPLAINER SETUP
# ================================
def initialize_shap_explainer():
    """Initialize SHAP explainer for the ensemble model"""
    global shap_explainer, background_data, feature_names
    
    try:
        # Try to load pre-computed explainer
        if os.path.exists(SHAP_EXPLAINER_PATH):
            print("[INFO] Loading pre-computed SHAP explainer...")
            shap_explainer = joblib.load(SHAP_EXPLAINER_PATH)
        else:
            print("[INFO] Creating new SHAP explainer...")
            # Load or create background data
            if os.path.exists(BACKGROUND_DATA_PATH):
                background_data = joblib.load(BACKGROUND_DATA_PATH)
                print(f"[INFO] Loaded background data with shape: {background_data.shape}")
            else:
                print("[WARNING] No background data found, creating synthetic background...")
                background_data = create_synthetic_background()
            
            # Create TreeExplainer for ensemble (works best with tree-based models)
            # Use the best performing model from ensemble for explanations
            best_model = ensemble.named_estimators_.get('xgboost', 
                        ensemble.named_estimators_.get('randomforest',
                        list(ensemble.named_estimators_.values())[0]))
            
            shap_explainer = shap.TreeExplainer(best_model, background_data, check_additivity=False)
            
            # Save explainer for future use
            joblib.dump(shap_explainer, SHAP_EXPLAINER_PATH)
            print("[INFO] SHAP explainer saved for future use")
        
        print("[INFO] SHAP explainer initialized successfully")
        return True
        
    except Exception as e:
        print(f"[ERROR] Failed to initialize SHAP explainer: {e}")
        return False

def create_synthetic_background(n_samples=100):
    """Create synthetic background data for SHAP if not available"""
    # Define the expected feature order
    expected_features = get_expected_features()
    
    # Create synthetic data with realistic ranges for PE file features
    np.random.seed(42)  # For reproducibility
    
    # Define realistic ranges for different feature types
    feature_ranges = {
        'Machine': (0, 65535),
        'SizeOfOptionalHeader': (0, 1000),
        'Characteristics': (0, 65535),
        'MajorLinkerVersion': (0, 255),
        'MinorLinkerVersion': (0, 255),
        'SizeOfCode': (1000, 10000000),
        'SizeOfInitializedData': (0, 5000000),
        'SizeOfUninitializedData': (0, 1000000),
        'AddressOfEntryPoint': (1000, 1000000),
        'BaseOfCode': (1000, 100000),
        'BaseOfData': (0, 1000000),
        'ImageBase': (400000, 10000000),
        'SectionAlignment': (512, 65536),
        'FileAlignment': (512, 65536),
        'SizeOfImage': (1000, 50000000),
        'SizeOfHeaders': (200, 10000),
        'Subsystem': (1, 20),
        'DllCharacteristics': (0, 65535),
        'LoaderFlags': (0, 1),
        'NumberOfRvaAndSizes': (0, 20),
        'SectionsNb': (1, 20),
        'ImportsNbDLL': (0, 100),
        'ImportsNb': (0, 1000),
        'ImportsNbOrdinal': (0, 100),
        'ExportNb': (0, 1000),
        'ResourcesNb': (0, 1000)
    }
    
    synthetic_data = []
    for _ in range(n_samples):
        sample = []
        for feature in expected_features:
            if feature in feature_ranges:
                low, high = feature_ranges[feature]
                if 'entropy' in feature.lower():
                    # Entropy features should be between 0 and 8
                    value = np.random.uniform(0, 8)
                elif 'ratio' in feature.lower():
                    # Ratio features should be between 0 and 10
                    value = np.random.uniform(0, 10)
                elif '_log' in feature:
                    # Log features should be positive
                    value = np.random.uniform(0, 15)
                else:
                    value = np.random.uniform(low, high)
            else:
                # Default range for unknown features
                value = np.random.uniform(0, 1000)
            sample.append(value)
        synthetic_data.append(sample)
    
    background_array = np.array(synthetic_data)
    # Scale the background data
    try:
        background_array = scaler.transform(background_array)
    except:
        pass
    
    # Save for future use
    joblib.dump(background_array, BACKGROUND_DATA_PATH)
    print(f"[INFO] Created and saved synthetic background data with shape: {background_array.shape}")
    
    return background_array

# ================================
# FEATURE ENGINEERING FUNCTIONS
# ================================
def get_expected_features():
    """Get the expected feature order"""
    expected_features = [
        'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion',
        'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData',
        'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode',
        'BaseOfData', 'ImageBase', 'SectionAlignment', 'FileAlignment',
        'SizeOfImage', 'SizeOfHeaders', 'Subsystem', 'DllCharacteristics',
        'LoaderFlags', 'NumberOfRvaAndSizes', 'SectionsNb', 'SectionsMeanEntropy',
        'SectionsMinEntropy', 'SectionsMaxEntropy', 'SectionsMeanRawsize',
        'SectionsMinRawsize', 'SectionMaxRawsize', 'SectionsMeanVirtualsize',
        'SectionsMinVirtualsize', 'SectionMaxVirtualsize', 'ImportsNbDLL',
        'ImportsNb', 'ImportsNbOrdinal', 'ExportNb', 'ResourcesNb',
        'ResourcesMeanEntropy', 'ResourcesMinEntropy', 'ResourcesMaxEntropy',
        'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize',
        'LoadConfigurationSize', 'VersionInformationSize',
        # Engineered features
        'code_to_image_ratio', 'init_to_code_ratio', 'sections_to_imports_ratio',
        'entropy_range', 'size_range', 'SizeOfCode_log', 'SizeOfImage_log',
        'SizeOfHeaders_log', 'entropy_sections_interaction', 'imports_exports_interaction'
    ]
    return expected_features

def create_engineered_features(features_dict):
    """Create engineered features from the raw features"""
    feature_dict = features_dict.copy()
    
    # Ratio features
    feature_dict['code_to_image_ratio'] = feature_dict.get('SizeOfCode', 0) / (feature_dict.get('SizeOfImage', 0) + 1)
    feature_dict['init_to_code_ratio'] = feature_dict.get('SizeOfInitializedData', 0) / (feature_dict.get('SizeOfCode', 0) + 1)
    feature_dict['sections_to_imports_ratio'] = feature_dict.get('SectionsNb', 0) / (feature_dict.get('ImportsNb', 0) + 1)
    
    # Range features
    feature_dict['entropy_range'] = feature_dict.get('SectionsMaxEntropy', 0) - feature_dict.get('SectionsMinEntropy', 0)
    feature_dict['size_range'] = feature_dict.get('SectionMaxRawsize', 0) - feature_dict.get('SectionsMinRawsize', 0)
    
    # Log features
    for col in ['SizeOfCode', 'SizeOfImage', 'SizeOfHeaders']:
        if col in feature_dict:
            feature_dict[f'{col}_log'] = np.log1p(feature_dict[col])
    
    # Interaction features
    feature_dict['entropy_sections_interaction'] = feature_dict.get('SectionsMeanEntropy', 0) * feature_dict.get('SectionsNb', 0)
    feature_dict['imports_exports_interaction'] = feature_dict.get('ImportsNb', 0) * feature_dict.get('ExportNb', 0)
    
    return feature_dict

def prepare_feature_vector(features_dict):
    """
    Prepare feature vector as numpy array in the exact order expected by the model
    """
    # Create engineered features
    engineered_features = create_engineered_features(features_dict)
    
    # Use saved feature columns if available, otherwise use expected order
    feature_order = feature_columns if feature_columns else get_expected_features()
    
    # Create feature vector in the correct order
    feature_vector = []
    for feature_name in feature_order:
        value = engineered_features.get(feature_name, 0)
        # Convert to float and handle any NaN values
        try:
            value = float(value)
            if np.isnan(value) or np.isinf(value):
                value = 0.0
        except (ValueError, TypeError):
            value = 0.0
        feature_vector.append(value)
    
    return np.array(feature_vector).reshape(1, -1)

def safe_model_predict(model, features):
    """Safely predict using a model, handling various edge cases"""
    try:
        pred = model.predict(features)
        proba = model.predict_proba(features)
        return pred[0], proba[0]
    except Exception as e:
        print(f"[WARNING] Model prediction failed: {e}")
        return 0, [0.7, 0.3]  # Default to benign

# ================================
# SHAP EXPLANATION FUNCTIONS
# ================================
def get_shap_explanation(features_scaled, top_n=10):
    """
    Generate SHAP explanations for the prediction
    """
    global shap_explainer, feature_names
    
    if shap_explainer is None:
        return None
    
    try:
        # Get SHAP values
        shap_values = shap_explainer.shap_values(features_scaled, check_additivity=False)
        
        # Handle different SHAP value formats
        if isinstance(shap_values, list):
            # Binary classification: use values for malicious class
            shap_vals = shap_values[1] if len(shap_values) > 1 else shap_values[0]
        else:
            # Single array
            shap_vals = shap_values
        
        # Get feature names
        feature_list = feature_names if feature_names else [f"feature_{i}" for i in range(len(shap_vals[0]))]
        
        # Create feature importance ranking
        feature_importance = []
        for i, (feature_name, importance) in enumerate(zip(feature_list, shap_vals[0])):
            feature_importance.append({
                'feature': feature_name,
                'importance': float(importance),
                'abs_importance': float(abs(importance)),
                'value': float(features_scaled[0][i]) if i < len(features_scaled[0]) else 0.0,
                'contribution': 'increases_risk' if importance > 0 else 'decreases_risk'
            })
        
        # Sort by absolute importance
        feature_importance.sort(key=lambda x: x['abs_importance'], reverse=True)
        
        # Return top N features
        return {
            'top_features': feature_importance[:top_n],
            'base_value': float(shap_explainer.expected_value[1] if hasattr(shap_explainer.expected_value, '__len__') else shap_explainer.expected_value),
            'prediction_explanation': generate_explanation_text(feature_importance[:top_n])
        }
        
    except Exception as e:
        print(f"[ERROR] SHAP explanation failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def generate_explanation_text(top_features):
    """Generate human-readable explanation from SHAP values"""
    if not top_features:
        return "Unable to generate explanation."
    
    explanations = []
    
    for feature in top_features[:5]:  # Top 5 most important features
        feature_name = feature['feature']
        importance = feature['importance']
        contribution = feature['contribution']
        
        # Create human-readable feature names
        readable_names = {
            # Header fields
            "Machine": "What processor type the program is meant for. Normally fixed for Windows apps.",
            "SizeOfOptionalHeader": "How big the file’s header is. Strange sizes may mean the file was modified.",
            "Characteristics": "Flags that describe the file. Unusual flag combinations can look odd.",
            "MajorLinkerVersion": "The version of the tool that built the file. Unusual versions may mean custom tools.",
            "MinorLinkerVersion": "Minor version of the tool. Rare values can stand out.",
            "SizeOfCode": "How much space the main code takes. Very big or very small sizes can be unusual.",
            "SizeOfInitializedData": "Stored data size. Odd values may mean the program hides extra content.",
            "SizeOfUninitializedData": "Reserved empty data. Large values can look strange.",
            "AddressOfEntryPoint": "Where the program starts running. Unexpected locations can look odd.",
            "BaseOfCode": "Where the code section begins. Strange placements may mean unusual structure.",
            "BaseOfData": "Where the data section begins. Uncommon positions may be worth noting.",
            "ImageBase": "Where the file prefers to load in memory. Most programs use the same spot, rare spots may stand out.",
            "SectionAlignment": "How parts of the file line up in memory. Strange values may suggest packing or compression.",
            "FileAlignment": "How file data is arranged on disk. Unusual layouts may hint at modification.",
            "SizeOfImage": "How big the program looks in memory. Very large or very small sizes may be unusual.",
            "SizeOfHeaders": "How big the file’s header is. Very odd sizes may hint at corruption or tampering.",
            "Subsystem": "The kind of program (like windowed app or console). Normal programs use expected values.",
            "DllCharacteristics": "Special settings for how the file runs. Some uncommon ones may stand out.",
            "LoaderFlags": "Settings almost never used. If present, they may look unusual.",
            "NumberOfRvaAndSizes": "How many internal tables the file has. Too many or too few can be strange.",

            # Section stats
            "SectionsNb": "How many parts the file has. Normal programs have a few; very high or low counts can be odd.",
            "SectionsMeanEntropy": "How jumbled the file parts look overall. Higher means more compressed or scrambled.",
            "SectionsMinEntropy": "The simplest part of the file. Very low means plain and easy to read.",
            "SectionsMaxEntropy": "The most scrambled part of the file. Very high can mean it’s compressed or hiding code.",
            "SectionsMeanRawsize": "Average size of file parts. Abnormal sizes may suggest something added or removed.",
            "SectionsMinRawsize": "Smallest part of the file. Tiny parts may be placeholders or hiding data.",
            "SectionMaxRawsize": "Largest part of the file. Very big parts may carry hidden content.",
            "SectionsMeanVirtualsize": "Average size in memory. Odd values may mean unusual mapping.",
            "SectionsMinVirtualsize": "Smallest memory section. Too small can be unusual.",
            "SectionMaxVirtualsize": "Largest memory section. Very large may mean injected code.",

            # Imports/Exports
            "ImportsNbDLL": "How many helper libraries the file uses. Normal programs import several; odd counts may stand out.",
            "ImportsNb": "How many outside functions it calls. Very high or very low use may be unusual.",
            "ImportsNbOrdinal": "A way of calling functions by number instead of name. Often used to hide what’s being called.",
            "ExportNb": "How many functions the file offers to others. Very unusual exports can be suspicious.",
            "ResourcesNb": "How many extras (like icons or images) are inside. Very high or very low counts may look odd.",
            "ResourcesMeanEntropy": "How scrambled the extras look. Higher may mean hidden data inside them.",
            "ResourcesMinEntropy": "Simplest extra data. Low values mean plain icons or text.",
            "ResourcesMaxEntropy": "Most scrambled extra data. High values may hide code.",
            "ResourcesMeanSize": "Average size of extras. Very big averages may mean unusual content.",
            "ResourcesMinSize": "Smallest extra. Very tiny can just be placeholders.",
            "ResourcesMaxSize": "Largest extra. Very large ones may hide files inside.",

            # Config & version
            "LoadConfigurationSize": "How much setup information the file carries. Abnormal sizes may stand out.",
            "VersionInformationSize": "How much descriptive info (like version or company) is stored. Normal programs have this; missing or strange sizes may look odd.",

            # Engineered
            "code_to_image_ratio": "How much of the file is actual code compared to total size. Odd ratios may mean padding or hidden content.",
            "init_to_code_ratio": "How much data vs code there is. Large amounts of data compared to code may be unusual.",
            "sections_to_imports_ratio": "Balance between number of file parts and number of outside functions used. Odd balances may mean unusual design.",
            "entropy_range": "How different the simplest and most scrambled parts are. Big differences mean mixed plain and packed parts.",
            "size_range": "How different the smallest and largest parts are. Very uneven sizes may be unusual.",
            "SizeOfCode_log": "Code size viewed on a log scale. Helps highlight very big or small code sizes.",
            "SizeOfImage_log": "Total size in memory viewed on a log scale. Shows unusually scaled programs.",
            "SizeOfHeaders_log": "Header size on a log scale. Odd values may hint at tampering.",
            "entropy_sections_interaction": "Mix between number of parts and how scrambled they are. Higher means a more complex structure.",
            "imports_exports_interaction": "Balance between what the file uses from others and what it provides. Odd balances may stand out."
        }
        
        readable_name = readable_names.get(feature_name, feature_name.replace('_', ' ').title())
        
        if contribution == 'increases_risk':
            explanations.append(f"• {readable_name} Suggests higher malware risk (impact: {abs(importance):.3f})")
        else:
            explanations.append(f"• {readable_name} Suggests lower malware risk (impact: {abs(importance):.3f})")
    
    return "\n".join(explanations)

def calculate_risk_score(probability_malicious, shap_explanation):
    """Calculate a comprehensive risk score"""
    base_score = probability_malicious * 100
    
    if shap_explanation:
        # Adjust based on feature confidence
        top_features = shap_explanation.get('top_features', [])
        if top_features:
            # Check if top features are consistent with prediction
            top_feature_directions = [f['contribution'] for f in top_features[:3]]
            consistency = sum(1 for contrib in top_feature_directions if 
                            (contrib == 'increases_risk' and probability_malicious > 0.5) or
                            (contrib == 'decreases_risk' and probability_malicious <= 0.5))
            
            consistency_factor = consistency / len(top_feature_directions) if top_feature_directions else 0.5
            base_score = base_score * (0.7 + 0.3 * consistency_factor)
    
    return min(100, max(0, base_score))

# ================================
# API ROUTE WITH CORS HEADERS AND SHAP
# ================================
@app.route("/analyze", methods=["POST"])
def analyze():
    start_time = time.time()
    # Add CORS headers to response
    response_headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS'
    }
    
    if "file" not in request.files:
        response = jsonify({"error": "No file uploaded"})
        for key, value in response_headers.items():
            response.headers[key] = value
        response.status_code = 400
        return response
    
    file = request.files["file"]
    if file.filename == '':
        response = jsonify({"error": "No file selected"})
        for key, value in response_headers.items():
            response.headers[key] = value
        response.status_code = 400
        return response

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        filepath = tmp.name
        file.save(filepath)

    try:
        # Validate PE file
        if not is_pe_file(filepath):
            response = jsonify({"error": "Not a valid PE file"})
            for key, value in response_headers.items():
                response.headers[key] = value
            response.status_code = 400
            return response

        # Extract features using your feature extraction
        print(f"[INFO] Analyzing file: {file.filename}")
        pe = pefile.PE(filepath)
        features_dict = extract_features(pe, filepath)
        pe.close()
        
        print(f"[INFO] Extracted {len(features_dict)} raw features")
        
        # Prepare feature vector as numpy array
        feature_vector = prepare_feature_vector(features_dict)
        print(f"[INFO] Prepared feature vector with shape: {feature_vector.shape}")
        
        # Scale features
        try:
            features_scaled = scaler.transform(feature_vector)
        except Exception as e:
            print(f"[WARNING] Scaling failed: {e}, using unscaled features")
            features_scaled = feature_vector
        
        # Make predictions with individual models and combine manually
        individual_predictions = []
        individual_probas = []
        model_weights = [3, 2, 1]  # XGB, RF, LR weights from your training
        
        for i, (name, model) in enumerate(ensemble.named_estimators_.items()):
            print(f"[INFO] Predicting with {name}...")
            pred, proba = safe_model_predict(model, features_scaled)
            individual_predictions.append(pred)
            individual_probas.append(proba)
        
        # Weighted average of probabilities
        weighted_probas = np.average(individual_probas, axis=0, weights=model_weights[:len(individual_probas)])
        final_prediction = 1 if weighted_probas[1] > 0.5 else 0
        confidence = float(np.max(weighted_probas))
        probability_malicious = float(weighted_probas[1])
        
        # Generate SHAP explanation
        print("[INFO] Generating SHAP explanation...")
        shap_explanation = get_shap_explanation(features_scaled)
        
        # Calculate comprehensive risk score
        risk_score = calculate_risk_score(probability_malicious, shap_explanation)
        
        # Determine threat level
        if risk_score >= 80:
            threat_level = "HIGH"
            threat_color = "#dc3545"  # Red
        elif risk_score >= 50:
            threat_level = "MEDIUM"
            threat_color = "#fd7e14"  # Orange
        elif risk_score >= 20:
            threat_level = "LOW"
            threat_color = "#ffc107"  # Yellow
        else:
            threat_level = "MINIMAL"
            threat_color = "#28a745"  # Green
        
        # Generate file hash for tracking
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Prepare result with enhanced information
        result = {
            "filename": file.filename,
            "verdict": "suspicious" if final_prediction == 1 else "clean",
            "confidence": round(confidence, 4),
            "probability_malicious": round(probability_malicious, 4),
            "probability_benign": round(float(weighted_probas[0]), 4),
            "risk_score": round(risk_score, 1),
            "threat_level": threat_level,
            "threat_color": threat_color,
            "detected_by": "EnsembleModel",
            "timestamp": datetime.utcnow().isoformat(),
            "file_hash": file_hash,
            "file_size": os.path.getsize(filepath),
            "model_predictions": {
                name: {
                    "prediction": int(pred),
                    "confidence": round(float(max(proba)), 4),
                    "probability_malicious": round(float(proba[1]), 4)
                }
                for name, pred, proba in zip(ensemble.named_estimators_.keys(), individual_predictions, individual_probas)
            },
            "explanation": shap_explanation,
            "analysis_metadata": {
                "feature_count": len(features_dict),
                "has_explanation": shap_explanation is not None
            }
        }
        
        # Calculate actual processing time
        # result["analysis_metadata"]["processing_time"] = round(time.time() - result["analysis_metadata"]["processing_time"], 3)
        result["analysis_metadata"]["processing_time"] = round(time.time() - start_time, 3)
        
        print(f"[INFO] Prediction complete: {result['verdict']} (confidence: {result['confidence']}, risk: {result['risk_score']})")
        
        response = jsonify(result)
        for key, value in response_headers.items():
            response.headers[key] = value
        return response

    except Exception as e:
        print(f"[ERROR] Analysis failed: {str(e)}")
        import traceback
        traceback.print_exc()
        
        response = jsonify({"error": f"Analysis failed: {str(e)}"})
        for key, value in response_headers.items():
            response.headers[key] = value
        response.status_code = 500
        return response
    
    finally:
        # Clean up temporary file
        if os.path.exists(filepath):
            os.remove(filepath)

# ================================
# HEALTH CHECK ROUTE
# ================================
@app.route("/health", methods=["GET"])
def health_check():
    response = jsonify({
        "status": "healthy",
        "model_loaded": ensemble is not None,
        "scaler_loaded": scaler is not None,
        "feature_columns": len(feature_columns) if feature_columns is not None else 0,
        "shap_ready": shap_explainer is not None,
        "capabilities": {
            "malware_detection": True,
            "explainable_ai": shap_explainer is not None,
            "risk_scoring": True,
            "multi_model_ensemble": True
        }
    })
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

# ================================
# ADDITIONAL API ENDPOINTS
# ================================
@app.route("/explain/<file_hash>", methods=["GET"])
def get_explanation(file_hash):
    """Get detailed explanation for a previously analyzed file"""
    # This would typically query a database, but for now return a message
    response = jsonify({
        "message": "Detailed explanations are included in the /analyze response",
        "file_hash": file_hash,
        "suggestion": "Re-analyze the file to get current explanations"
    })
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

# ================================
# RUN SERVER
# ================================
if __name__ == "__main__":
    print("[INFO] Starting enhanced malware detection server...")
    print(f"[INFO] Model components loaded successfully")
    
    # Initialize SHAP explainer
    print("[INFO] Initializing SHAP explainer...")
    if initialize_shap_explainer():
        print("[INFO] SHAP explainer ready - explanations enabled")
    else:
        print("[WARNING] SHAP explainer not available - running without explanations")
    
    print(f"[INFO] Server ready to analyze PE files with AI explanations")
    app.run(debug=True, host='0.0.0.0', port=5000)