from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd
from openai import OpenAI
from datetime import datetime
import random
from dotenv import load_dotenv
import os
import re

load_dotenv()
app = Flask(__name__)
CORS(app)
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
file_path = '../archive/GUIDE_Test.csv'
df = pd.read_csv(file_path, low_memory=False)
log_attack_techniques = []
attack_technique_counts = {}


def extract_attack_technique_id(response_content):
    attack_technique_ids = re.findall(r'\bT\d{4}\b', response_content)
    return attack_technique_ids if attack_technique_ids else None


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
    incident_grade = random.choice(incident_grades)  # Randomly choose an IncidentGrade
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


@app.route('/predict-attack-technique', methods=['GET'])
def predict_attack_technique():
    return jsonify(attack_technique_counts)


if __name__ == '__main__':
    app.run(debug=True)
