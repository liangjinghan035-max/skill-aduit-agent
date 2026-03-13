"""Model Loader Skill - Load and run ML models."""
import pickle
import os

MODEL_DIR = os.path.expanduser("~/models")

def load_model(model_name):
    """Load a pickled ML model.
    
    WARNING: pickle.load() can execute arbitrary code.
    Only load models from trusted sources.
    """
    model_path = os.path.join(MODEL_DIR, f"{model_name}.pkl")
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model {model_name} not found")
    
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    
    return model

def predict(model_name, data):
    """Run prediction with a loaded model."""
    model = load_model(model_name)
    return model.predict(data)
