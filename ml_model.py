import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

def train_model():
    # Load traffic data
    data = pd.read_csv('data/traffic_data.csv', header=None)
    data.columns = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'packet_size', 'label']  # Include 'label' for training

    # Preprocessing: Select potential features
    X = data[['protocol', 'packet_size']]  # Add more features if available
    y = data['label']

    # Apply feature selection
    selector = SelectKBest(score_func=f_classif, k='all')  # Choose top 'k' features
    X_selected = selector.fit_transform(X, y)

    # Display selected features and their scores
    feature_scores = zip(X.columns, selector.scores_)
    for feature, score in feature_scores:
        print(f"Feature: {feature}, Score: {score}")

    # Split the dataset
    X_train, X_test, y_train, y_test = train_test_split(X_selected, y, test_size=0.2)

    # Train Random Forest Classifier
    model = RandomForestClassifier()
    model.fit(X_train, y_train)

    # Evaluate the model
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    # Save the model (optional)
    return model
