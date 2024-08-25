import stix2
from stix2 import Filter, MemoryStore

# Define paths to the JSON files
paths = {
    'enterprise': 'D:\\Python Files\\JAIMITRE\\FlaskBackend\\attack-stix-data\\enterprise-attack\\enterprise-attack.json',
    'ics': 'D:\\Python Files\\JAIMITRE\\FlaskBackend\\attack-stix-data\\ics-attack\\ics-attack.json',
    'mobile': 'D:\\Python Files\\JAIMITRE\\FlaskBackend\\attack-stix-data\\mobile-attack\\mobile-attack.json'
}

# Create MemoryStore instances for each domain
data_stores = {
    'enterprise': MemoryStore(),
    'ics': MemoryStore(),
    'mobile': MemoryStore()
}

# Load data into the corresponding stores
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


def search_techniques_by_content(stores, search_content):
    # Query all stores for attack-patterns
    all_techniques = query_all_stores(stores, 'attack-pattern')
    # Filter techniques based on content in their description, if description exists
    matching_techniques = []
    for tech in all_techniques:
        if 'description' in tech and search_content.lower() in tech.description.lower():
            matching_techniques.append(tech)
    return matching_techniques


def find_intrusion_set_by_external_id(stores, external_id):
    intrusion_sets = []
    for store_name, store in stores.items():
        results = store.query([Filter('external_references.external_id', '=', external_id)])
        intrusion_sets.extend(results)
    return intrusion_sets


# Example usage
g0075_intrusion_sets = find_intrusion_set_by_external_id(data_stores, "G0075")

# Print results for the intrusion set
for intrusion_set in g0075_intrusion_sets:
    print(
        f"ID: {intrusion_set.id}, Name: {intrusion_set.name}, Description: {intrusion_set.get('description', 'No description available')}")

# Search for techniques with content 'LSASS'
matching_techniques = search_techniques_by_content(data_stores, 'LSASS')
for technique in matching_techniques:
    print(
        f"ID: {technique.id}, Name: {technique.name}, Description: {technique.get('description', 'No description available')}")
