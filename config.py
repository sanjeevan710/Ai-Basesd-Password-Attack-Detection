import os

class Config:
    # Fixed secret key — sessions survive server restarts
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ai-shield-mca-project-2024-static-key-x9k2p'

    # CSRF Protection
    WTF_CSRF_ENABLED = True

    # ML Model Paths (relative to app root)
    MODEL_PATH_RF = 'models/random_forest_model.pkl'
    MODEL_PATH_LR = 'models/logistic_regression_model.pkl'