import pandas as pd 
import numpy as np 
from sklearn.model_selection import train_test_split 
from sklearn.ensemble import RandomForestClassifier 
from sklearn.linear_model import LogisticRegression 
from sklearn.metrics import accuracy_score, classification_report 
import joblib 
import os 
 
# Create models directory if it doesn't exist 
if not os.path.exists('models'): 
    os.makedirs('models') 
 
print("Generating synthetic dataset...") 
# Features: 
# 1. failed_attempts: Number of failed login attempts in the last hour
# 2. login_frequency: Number of logins in the last 24 hours 
# 3. access_time_hour: Hour of the day (0-23) 
# 4. is_new_device: 1 if new device, 0 if known 
# 5. is_suspicious_ip: 1 if IP is flagged/different region, 0 if normal 
# 6. location_change: 1 if location changed significantly, 0 if not 
 
# Target: 0 (Normal), 1 (Attack/Suspicious) 
 
np.random.seed(42) 
n_samples = 5000 
 
data = { 
    'failed_attempts': [], 
    'login_frequency': [], 
    'access_time_hour': [], 
    'is_new_device': [], 
    'is_suspicious_ip': [], 
    'location_change': [], 
    'label': [] 
} 
 
for _ in range(n_samples): 
    label = np.random.choice([0, 1], p=[0.7, 0.3]) # 70% normal, 30% attack 
 
    if label == 0: # Normal behavior 
        data['failed_attempts'].append(np.random.choice([0, 1, 2], p=[0.8, 0.15, 0.05])) 
        data['login_frequency'].append(np.random.randint(1, 5)) 
        data['access_time_hour'].append(np.random.randint(6, 23)) # Mostly day time 
        data['is_new_device'].append(np.random.choice([0, 1], p=[0.9, 0.1])) 
        data['is_suspicious_ip'].append(0) 
        data['location_change'].append(np.random.choice([0, 1], p=[0.95, 0.05])) 
    else: # Attack behavior 
        data['failed_attempts'].append(np.random.randint(3, 15)) # High failed attempts 
        data['login_frequency'].append(np.random.randint(5, 50)) # High frequency 
        data['access_time_hour'].append(np.random.randint(0, 24)) # Any time (often night) 
        data['is_new_device'].append(1) # Often new device 
        data['is_suspicious_ip'].append(np.random.choice([0, 1], p=[0.4, 0.6])) 
        data['location_change'].append(np.random.choice([0, 1], p=[0.3, 0.7]))
 
    data['label'].append(label) 
 
df = pd.DataFrame(data) 
 
# Split data 
X = df.drop('label', axis=1) 
y = df['label'] 
 
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42) 
 
# Train Random Forest
print("Training Random Forest...") 
rf_model = RandomForestClassifier(n_estimators=100, random_state=42) 
rf_model.fit(X_train, y_train) 
 
# Evaluate 
y_pred_rf = rf_model.predict(X_test) 
print("Random Forest Accuracy:", accuracy_score(y_test, y_pred_rf)) 
print(classification_report(y_test, y_pred_rf)) 
 
# Train Logistic Regression 
print("Training Logistic Regression...") 
lr_model = LogisticRegression(random_state=42) 
lr_model.fit(X_train, y_train) 
 
y_pred_lr = lr_model.predict(X_test) 
print("Logistic Regression Accuracy:", accuracy_score(y_test, y_pred_lr)) 
 
# Save models 
print("Saving models...") 
joblib.dump(rf_model, 'models/random_forest_model.pkl') 
joblib.dump(lr_model, 'models/logistic_regression_model.pkl') 
print("Models saved successfully in 'models/' directory.") 