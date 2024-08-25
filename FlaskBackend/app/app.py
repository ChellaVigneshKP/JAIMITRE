from flask import Flask, request, jsonify
from flask_cors import CORS
from stix2 import MemoryStore, Filter
import os

app = Flask(__name__)

# Configure CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# Define local paths for ATT&CK data
paths = {
    'enterprise': '../attack-stix-data/enterprise-attack/enterprise-attack.json',
    'ics': '../attack-stix-data/ics-attack/ics-attack.json',
    'mobile': '../attack-stix-data/mobile-attack/mobile-attack.json'
}


# Load the ATT&CK data into the MemoryStore
def load_data(domain, version=None):
    """Load ATT&CK data for a given domain and version."""
    if domain not in paths:
        raise ValueError(f"Invalid domain: {domain}. Expected one of {list(paths.keys())}.")

    file_path = paths[domain]
    if version:
        file_path = file_path.replace('.json', f'-{version}.json')

    if os.path.exists(file_path):
        ms = MemoryStore()
        ms.load_from_file(file_path)
    else:
        raise FileNotFoundError(f"File not found: {file_path}")

    return ms


# Initialize the data store
domain = 'enterprise'  # Change this to the domain you want to work with
try:
    src = load_data(domain)
except (ValueError, FileNotFoundError) as e:
    print(f"Error loading data: {e}")
    src = None  # Initialize src to None if data loading fails


@app.after_request
def after_request(response):
    """Add CORS headers to responses."""
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    return response


@app.route('/object/<stix_id>', methods=['GET', 'POST', 'OPTIONS'])
def get_object_by_stix_id(stix_id):
    if request.method == 'OPTIONS':
        return '', 204
    if not src:
        return jsonify({"error": "Data source not initialized"}), 500
    obj = src.get(stix_id)
    if obj:
        return jsonify(obj.serialize()), 200
    return jsonify({"error": "Object not found"}), 404


@app.route('/attack-id/<string:attack_id>', methods=['GET', 'POST', 'OPTIONS'])
def get_object_by_attack_id(attack_id):
    if request.method == 'OPTIONS':
        return '', 204
    if not src:
        return jsonify({"error": "Data source not initialized"}), 500
    objs = src.query([Filter("external_references.external_id", "=", attack_id)])
    if objs:
        return jsonify([obj.serialize() for obj in objs]), 200
    return jsonify({"error": "Object not found"}), 404


@app.route('/name/<name>', methods=['GET', 'POST', 'OPTIONS'])
def get_object_by_name(name):
    if request.method == 'OPTIONS':
        return '', 204
    if not src:
        return jsonify({"error": "Data source not initialized"}), 500
    filt = [Filter('type', '=', 'attack-pattern'), Filter('name', '=', name)]
    objs = src.query(filt)
    if objs:
        return jsonify([obj.serialize() for obj in objs]), 200
    return jsonify({"error": "Object not found"}), 404


@app.route('/alias/<alias>', methods=['GET', 'POST', 'OPTIONS'])
def get_object_by_alias(alias):
    if request.method == 'OPTIONS':
        return '', 204
    if not src:
        return jsonify({"error": "Data source not initialized"}), 500
    filt = [Filter('type', '=', 'intrusion-set'), Filter('aliases', '=', alias)]
    objs = src.query(filt)
    if objs:
        return jsonify([obj.serialize() for obj in objs]), 200
    return jsonify({"error": "Object not found"}), 404


@app.route('/type/<stix_type>', methods=['GET', 'POST', 'OPTIONS'])
def get_objects_by_type(stix_type):
    if request.method == 'OPTIONS':
        return '', 204
    if not src:
        return jsonify({"error": "Data source not initialized"}), 500
    objs = src.query([Filter("type", "=", stix_type)])
    if objs:
        return jsonify([obj.serialize() for obj in objs]), 200
    return jsonify({"error": "Objects not found"}), 404


@app.route('/techniques', methods=['GET', 'POST', 'OPTIONS'])
def get_techniques():
    if request.method == 'OPTIONS':
        return '', 204
    if not src:
        return jsonify({"error": "Data source not initialized"}), 500
    include = request.args.get('include', 'both')
    if include not in ["techniques", "subtechniques", "both"]:
        return jsonify({"error": "Invalid 'include' parameter"}), 400
    return jsonify([obj.serialize() for obj in get_techniques_or_subtechniques(src, include)]), 200


@app.route('/software', methods=['GET', 'POST', 'OPTIONS'])
def get_software_info():
    if request.method == 'OPTIONS':
        return '', 204
    if not src:
        return jsonify({"error": "Data source not initialized"}), 500
    return jsonify([obj.serialize() for obj in get_software(src)]), 200


@app.route('/content', methods=['GET', 'POST', 'OPTIONS'])
def get_techniques_by_content_route():
    if request.method == 'OPTIONS':
        return '', 204
    if not src:
        return jsonify({"error": "Data source not initialized"}), 500
    content = request.args.get('content')
    if not content:
        return jsonify({"error": "Missing 'content' parameter"}), 400
    return jsonify([obj.serialize() for obj in get_techniques_by_content(src, content)]), 200


@app.route('/platform/<platform>', methods=['GET', 'POST', 'OPTIONS'])
def get_techniques_by_platform_route(platform):
    if request.method == 'OPTIONS':
        return '', 204
    if not src:
        return jsonify({"error": "Data source not initialized"}), 500
    return jsonify([obj.serialize() for obj in get_techniques_by_platform(src, platform)]), 200


@app.route('/tactic/<tactic>', methods=['GET', 'POST', 'OPTIONS'])
def get_tactic_techniques_route(tactic):
    if request.method == 'OPTIONS':
        return '', 204
    if not src:
        return jsonify({"error": "Data source not initialized"}), 500
    return jsonify([obj.serialize() for obj in get_tactic_techniques(src, tactic)]), 200


# Helper functions
def get_techniques_or_subtechniques(thesrc, include="both"):
    """Filter Techniques or Sub-Techniques from ATT&CK Enterprise Domain."""
    if include == "techniques":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', False)
        ])
    elif include == "subtechniques":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', True)
        ])
    elif include == "both":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern')
        ])
    else:
        return []  # Return an empty list if include parameter is invalid

    return query_results


def get_software(thesrc):
    """Get all software (tools and malware) from ATT&CK data."""
    from itertools import chain
    return list(chain.from_iterable(
        thesrc.query(f) for f in [
            Filter("type", "=", "tool"),
            Filter("type", "=", "malware")
        ]
    ))


def get_techniques_by_content(thesrc, content):
    """Get techniques by content description."""
    techniques = thesrc.query([Filter('type', '=', 'attack-pattern')])
    return [t for t in techniques if content.lower() in t.description.lower()]


def get_techniques_by_platform(thesrc, platform):
    """Get techniques by platform."""
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('x_mitre_platforms', '=', platform)
    ])


def get_tactic_techniques(thesrc, tactic):
    """Get techniques by tactic."""
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('kill_chain_phases.phase_name', '=', tactic),
        Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
    ])


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
