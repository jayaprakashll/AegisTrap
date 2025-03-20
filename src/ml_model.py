
import numpy as np
import joblib
import tensorflow as tf
from sklearn.preprocessing import StandardScaler

class MalwareClassifier:
    def __init__(self, model_path, scaler_path):
        self.model = tf.keras.models.load_model(model_path)
        self.scaler = joblib.load(scaler_path)
    
    def preprocess(self, features):
        feature_values = np.array([features.get(k, 0) for k in sorted(features.keys())]).reshape(1, -1)
        return self.scaler.transform(feature_values)
    
    def predict(self, features):
        processed_features = self.preprocess(features)
        prediction = self.model.predict(processed_features)
        return float(prediction[0][0])
    
    def batch_predict(self, feature_list):
        processed_batch = np.array([self.preprocess(features) for features in feature_list])
        predictions = self.model.predict(processed_batch)
        return [float(pred[0]) for pred in predictions]
    
    def save_model(self, save_path):
        self.model.save(save_path)
    
    def save_scaler(self, save_path):
        joblib.dump(self.scaler, save_path)
    
    def load_new_model(self, new_model_path):
        self.model = tf.keras.models.load_model(new_model_path)
    
    def load_new_scaler(self, new_scaler_path):
        self.scaler = joblib.load(new_scaler_path)
