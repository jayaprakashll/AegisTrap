import tensorflow as tf
import pickle

keras_model = tf.keras.models.load_model("model.keras")

model_data = {
    "architecture": keras_model.to_json(), 
    "weights": keras_model.get_weights()   
}

with open("model.pkl", "wb") as f:
    pickle.dump(model_data, f)

print("Model successfully converted to model.pkl")

