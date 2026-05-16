import joblib

scaler = joblib.load('robust_scaler.pkl')
print("Feature names from scaler:", scaler.feature_names_in_)