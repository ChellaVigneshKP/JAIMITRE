import joblib
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd
from openai import OpenAI
from datetime import datetime
import random
from dotenv import load_dotenv
import os
import re
import numpy as np
from stix2 import Filter, MemoryStore
import matplotlib.pyplot as plt
from scipy.sparse import hstack, csr_matrix
from sklearn.preprocessing import OneHotEncoder, LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, ConfusionMatrixDisplay
from catboost import CatBoostClassifier

le_cat_columns = ['Category', 'EntityType', 'EvidenceRole', 'SuspicionLevel', 'LastVerdict',
                  'ResourceType', 'Roles', 'AntispamDirection', 'ThreatFamily', 'CountryCode',
                  'OSFamily', 'OSVersion', 'State', 'City', 'RegistryValueName', 'RegistryValueData',
                  'ResourceIdName', 'RegistryKey', 'OAuthApplicationId', 'ApplicationId', 'ApplicationName']

numerical_columns = ['DeviceId', 'Sha256', 'IpAddress', 'Url', 'AccountSid', 'AccountUpn', 'AccountObjectId',
                     'AccountName', 'DeviceName', 'NetworkMessageId', 'EmailClusterId', 'FileName', 'FolderPath']

le_cat_columns += numerical_columns

numerical_columns = []

ohe_cat_columns = []


def preprocess_data(df, le_cat_columns):
    """
        This function preprocesses the dataset
    """
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    for le_col in le_cat_columns:
        df[le_col] = df[le_col].astype('object')
    return df


def process_data():
    train_data = pd.read_csv('../archive/GUIDE_Train.csv')
    test_data = pd.read_csv('../archive/GUIDE_Test.csv')
    print(train_data.shape)
    train_data.dropna(subset=['IncidentGrade'], inplace=True)
    train_data = preprocess_data(train_data, le_cat_columns)
    test_data = preprocess_data(test_data, le_cat_columns)
    group_columns = ohe_cat_columns + numerical_columns + le_cat_columns
    train_data = train_data.drop_duplicates(subset=group_columns)
    test_data.drop(['Usage'], axis=1, inplace=True)
    print(train_data.shape)
    print(test_data.shape)
    ohe = OneHotEncoder(handle_unknown='ignore')
    ohe.fit(train_data[ohe_cat_columns])
    train_data_ohe = csr_matrix(ohe.transform(train_data[ohe_cat_columns]))
    test_data_ohe = csr_matrix(ohe.transform(test_data[ohe_cat_columns]))
    train_data_numerical = csr_matrix(train_data[numerical_columns].fillna(-1).values)
    test_data_numerical = csr_matrix(test_data[numerical_columns].fillna(-1).values)
    feature_le = LabelEncoder()
    train_data_le = pd.DataFrame()
    test_data_le = pd.DataFrame()
    for le_col in le_cat_columns:
        feature_le.fit(pd.concat([train_data[le_col], test_data[le_col]]))
        train_data_le[le_col] = feature_le.transform(train_data[le_col])
        test_data_le[le_col] = feature_le.transform(test_data[le_col])
    train_data_le = csr_matrix(train_data_le)
    test_data_le = csr_matrix(test_data_le)
    X_train = hstack([train_data_ohe, train_data_le, train_data_numerical])
    X_test = hstack([test_data_ohe, test_data_le, test_data_numerical])
    target_le = LabelEncoder()
    target_le.fit(train_data['IncidentGrade'])
    y_train = target_le.transform(train_data['IncidentGrade'])
    y_test = target_le.transform(test_data['IncidentGrade'])
    """
        0: 'BenignPositive'
        1: 'FalsePositive'
        2: 'TruePositive'
    """
    print(f"Target Classes: {target_le.classes_}")
    return X_train, y_train, X_test, y_test


X_train, y_train, X_test, y_test = process_data()


def predict(model, X_test, y_test):
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else y_pred
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    cm_display = ConfusionMatrixDisplay(confusion_matrix=cm,
                                        display_labels=['BenignPositive', 'FalsePositive', 'TruePositive'])
    cm_display.plot()
    plt.show()

    return y_pred


def train_catboost_classifier(X_train, y_train):
    model = CatBoostClassifier(iterations=100, depth=5, random_seed=0, verbose=0)

    model.fit(X_train, y_train)
    importances = model.get_feature_importance()

    feature_columns = np.array(ohe_cat_columns + le_cat_columns + numerical_columns)
    indices = np.argsort(importances)[::-1]
    plt.figure(figsize=(12, 6))
    plt.title("Feature Importances (CatBoost Classifier)")
    plt.bar(range(X_train.shape[1]), importances[indices], align="center")
    plt.xticks(range(X_train.shape[1]), feature_columns[indices], rotation=90)
    plt.xlim([-1, X_train.shape[1]])
    plt.show()

    return model

paths = {
    'enterprise': '../attack-stix-data/enterprise-attack/enterprise-attack.json',
    'ics': '../attack-stix-data/ics-attack/ics-attack.json',
    'mobile': '../attack-stix-data/mobile-attack/mobile-attack.json'
}

d3fend_path = 'D:\\Python Files\\JAIMITRE\\FlaskBackend\\d3fend\\d3fend.csv'
d3df = pd.read_csv(d3fend_path)

data_stores = {
    'enterprise': MemoryStore(),
    'ics': MemoryStore(),
    'mobile': MemoryStore()
}
for domain, file_path in paths.items():
    data_stores[domain].load_from_file(file_path)


def query_all_stores(stores, query_type, filter_criteria=None):
    combined_results = []
    for store_name, store in stores.items():
        if filter_criteria is None:
            combined_results.extend(store.query([Filter('type', '=', query_type)]))
        else:
            combined_results.extend(store.query([Filter('type', '=', query_type)]))
    return combined_results


c_model = joblib.load("..\\best_catboost_model.pkl")


def search_techniques_by_content(stores, search_content):
    all_techniques = query_all_stores(stores, 'attack-pattern')
    matching_techniques = []
    for tech in all_techniques:
        if 'description' in tech and search_content.lower() in tech.description.lower():
            matching_techniques.append({
                'id': tech.id,
                'name': tech.name,
                'description': tech.get('description', 'No description available')
            })
    return matching_techniques


load_dotenv()
app = Flask(__name__)
CORS(app)
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
file_path = '../archive/GUIDE_Test.csv'
df = pd.read_csv(file_path, low_memory=False)
log_attack_techniques = []
attack_technique_counts = {}


def get_d3fend_technique(search_id):
    row = d3df[d3df['ID'] == search_id]
    if not row.empty:
        technique = row['D3FEND Technique'].values[0]
        if pd.isna(technique):
            return row['D3FEND Technique Level 0'].values[0]
        else:
            return technique
    else:
        return None


def call_d3fend_api(technique_name):
    # Remove spaces in the technique name
    technique_name_no_spaces = technique_name.replace(' ', '')
    url = f"https://d3fend.mitre.org/api/technique/d3f:{technique_name_no_spaces}.json"

    # Call the API
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Unable to retrieve data. Status code {response.status_code}"}


@app.route('/search-d3fendid', methods=['POST'])
def search_d3fend_by_id():
    data = request.json
    search_id = data.get('id')

    if not search_id:
        return jsonify({"error": "ID is required"}), 400

    technique_name = get_d3fend_technique(search_id)
    if technique_name:
        api_response = call_d3fend_api(technique_name)
        return jsonify({
            "technique_name": technique_name,
            "api_response": api_response
        }), 200
    else:
        return jsonify({"error": "D3FEND technique not found for the provided ID"}), 404


@app.route('/search-d3fendname', methods=['POST'])
def search_d3fend_by_name():
    data = request.json
    technique_name = data.get('name')

    if technique_name:
        api_response = call_d3fend_api(technique_name)
        return jsonify({
            "technique_name": technique_name,
            "api_response": api_response
        }), 200
    else:
        return jsonify({"error": "D3FEND technique not found for the provided ID"}), 404


def extract_attack_technique_id(response_content):
    attack_technique_ids = re.findall(r'\bT\d{4}(?:\.\d{3})?\b', response_content)
    return attack_technique_ids if attack_technique_ids else None


@app.route('/search-attackid', methods=['POST'])
def search_attackid():
    attack_ids_input = request.json.get('ids', [])
    print(f"Raw input received: {attack_ids_input}")

    attack_ids = []
    if isinstance(attack_ids_input, list):
        for item in attack_ids_input:
            if isinstance(item, str):
                attack_ids.extend([id.strip() for id in item.split(',')])
    elif isinstance(attack_ids_input, str):
        attack_ids = [id.strip() for id in attack_ids_input.split(',')]
    else:
        return jsonify({'error': 'Attack IDs should be a comma-separated string or a list of strings.'}), 400

    print(f"Parsed attack IDs: {attack_ids}")

    if not attack_ids or not all(isinstance(attack_id, str) for attack_id in attack_ids):
        return jsonify({'error': 'All attack IDs should be strings.'}), 400

    matching_techniques = []

    for attack_id in attack_ids:
        found = False
        for domain, store in data_stores.items():
            results = store.query([
                Filter("external_references.external_id", "=", attack_id),
                Filter("type", "=", "attack-pattern")
            ])
            if results:
                found = True
                technique = results[0]
                # Convert KillChainPhase to a serializable format
                kill_chain_phases = [
                    {
                        'kill_chain_name': phase.kill_chain_name,
                        'phase_name': phase.phase_name
                    }
                    for phase in technique.kill_chain_phases
                ]
                matching_techniques.append({
                    'attack_id': attack_id,  # Include the attack_id here
                    'id': technique.id,
                    'name': technique.name,
                    'description': technique.get('description', 'No description available'),
                    'type': technique.type,
                    'created': technique.created,
                    'modified': technique.modified,
                    'kill_chain_phases': kill_chain_phases
                })

        if not found:
            print(f"No results found for attack ID: {attack_id}")

    if not matching_techniques:
        return jsonify({'message': 'No matching techniques found.'}), 404

    return jsonify(matching_techniques)


@app.route('/search-content', methods=['POST'])
def search_technique():
    search_content = request.json.get('content', '')
    if not search_content:
        return jsonify({'error': 'Search content is required.'}), 400

    matching_techniques = search_techniques_by_content(data_stores, search_content)
    if not matching_techniques:
        return jsonify({'message': 'No matching techniques found.'}), 404

    return jsonify(matching_techniques)


@app.route('/generate-log', methods=['GET'])
def generate_log():
    random_row = df.sample(n=1).iloc[0]
    random_row = random_row.drop(labels=['IncidentGrade', 'MitreTechniques'])
    client_id = random_row.get('Id', 'UnknownClientID')
    log_dict = random_row.to_dict()
    if 'Timestamp' in log_dict:
        log_dict['Timestamp'] = datetime.strptime(log_dict['Timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ").strftime(
            "%m/%d %H:%M:%S")
    log_lines = [
        f"{log_dict['Timestamp']} INFO :module: ClientID: {client_id} {key}: {value if value is not None else ''}"
        for key, value in log_dict.items()]

    log_data = "\n".join(log_lines)
    formatted_json = {k: (v if pd.notna(v) else None) for k, v in log_dict.items()}
    incident_grades = ['BenignPositive', 'FalsePositive', 'TruePositive']
    incident_grade = random.choice(incident_grades)
    if incident_grade != 'FalsePositive':
        try:
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system",
                     "content": "You are a helpful assistant knowledgeable in MITRE ATT&CK techniques."},
                    {"role": "user",
                     "content": f"Based on the following log, predict the MITRE ATT&CK technique. Ensure to include the technique ID (e.g., T1566) in your response:\n{log_data} "}
                ]
            )
            response_content = response.choices[0].message.content.strip()
            print(response_content)
            attack_techniques = extract_attack_technique_id(response_content)
        except Exception as e:
            print(f"Error predicting ATT&CK Technique: {e}")
            attack_techniques = "Error: Unable to get response from ChatGPT."
    else:
        attack_techniques = None
    log_entry = {
        'log_data': log_data,
        'data_frame': formatted_json,
        'attack_technique': attack_techniques
    }
    log_attack_techniques.append(log_entry)

    if attack_techniques:
        for technique in attack_techniques:
            if technique in attack_technique_counts:
                attack_technique_counts[technique] += 1
            else:
                attack_technique_counts[technique] = 1
    return jsonify({
        'log_data': log_data,
        'data_frame': formatted_json,
        'incident_grade': incident_grade,
        'attack_technique': attack_techniques
    })


@app.route('/suggest-d3fend', methods=['POST'])
def suggest_d3fend():
    data = request.json
    attack_ids = data.get('attack_ids', [])

    if not attack_ids:
        return jsonify({'error': 'Attack IDs are required.'}), 400
    prompt = (
        "You are a knowledgeable assistant on MITRE ATT&CK and D3Fend tactics. For each MITRE ATT&CK technique ID provided, "
        "please provide a detailed report in plain text that includes the following information:\n\n"
        "1. Technique ID and Name\n"
        "2. D3Fend Tactics\n"
        "3. Detailed Recommendations for each tactic\n\n"
        "Here are the MITRE ATT&CK techniques for which I need detailed D3Fend tactics and recommendations:\n"
        f"{', '.join(attack_ids)}\n\n"
        "Please ensure that each technique is addressed with specific and actionable recommendations for the D3Fend tactics. Avoid markdown or special characters."
    )

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system",
                 "content": "You are a helpful assistant knowledgeable about MITRE ATT&CK and D3Fend tactics."},
                {"role": "user",
                 "content": prompt}
            ]
        )

        suggestions = response.choices[0].message.content.strip()

        return jsonify({'suggestions': suggestions})

    except Exception as e:
        print(f"Error getting D3Fend suggestions: {e}")
        return jsonify({'error': 'Failed to get D3Fend suggestions.'}), 500


@app.route('/predict-attack-technique', methods=['GET'])
def predict_attack_technique():
    return jsonify(attack_technique_counts)


if __name__ == '__main__':
    app.run(debug=True)
