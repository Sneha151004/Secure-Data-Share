import numpy as np
import pandas as pd
from typing import Union, Dict, List
import json

class DifferentialPrivacy:
    def __init__(self, epsilon: float = 1.0, sensitivity: float = 1.0, noise_level: float = 0.1):
        self.epsilon = epsilon
        self.sensitivity = sensitivity
        self.noise_level = noise_level

    def add_laplace_noise(self, data: np.ndarray) -> np.ndarray:
        """Add Laplace noise to numeric data"""
        scale = self.sensitivity / (self.epsilon * (1 - self.noise_level))
        noise = np.random.laplace(0, scale, data.shape)
        return data + noise

    def add_categorical_noise(self, data: pd.Series) -> pd.Series:
        """Add noise to categorical data by random substitution"""
        categories = data.unique()
        noise_mask = np.random.random(len(data)) < self.noise_level
        random_categories = np.random.choice(categories, size=sum(noise_mask))
        noisy_data = data.copy()
        noisy_data[noise_mask] = random_categories
        return noisy_data

    def process_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Process a pandas DataFrame with differential privacy"""
        private_df = df.copy()
        
        # Process numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            private_df[col] = self.add_laplace_noise(df[col].values)
        
        # Process categorical columns
        categorical_cols = df.select_dtypes(include=['object', 'category']).columns
        for col in categorical_cols:
            private_df[col] = self.add_categorical_noise(df[col])
            
        return private_df

    def process_json(self, json_data: Union[Dict, List]) -> Union[Dict, List]:
        """Process JSON data with differential privacy"""
        # Convert JSON to DataFrame if possible
        try:
            df = pd.DataFrame(json_data)
            private_df = self.process_dataframe(df)
            return private_df.to_dict('records') if isinstance(json_data, list) else private_df.to_dict()
        except:
            # If conversion fails, return original data with warning
            print("Warning: Could not apply differential privacy to this JSON structure")
            return json_data

def process_file_with_privacy(file_path: str, epsilon: float, noise_level: float) -> Union[pd.DataFrame, Dict]:
    """Process a file (CSV or JSON) with differential privacy"""
    dp = DifferentialPrivacy(epsilon=epsilon, noise_level=noise_level)
    
    if file_path.endswith('.csv'):
        df = pd.read_csv(file_path)
        return dp.process_dataframe(df)
    elif file_path.endswith('.json'):
        with open(file_path, 'r') as f:
            json_data = json.load(f)
        return dp.process_json(json_data)
    else:
        raise ValueError("Unsupported file type. Only CSV and JSON are supported.")