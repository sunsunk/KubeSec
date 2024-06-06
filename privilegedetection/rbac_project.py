import json
import os
from collections import defaultdict

def load_data(file_path):
    loaded_data = []
    with open(file_path, "r") as json_file:
        for line in json_file:
            data = json.loads(line)
            loaded_data.append(data)
    return loaded_data

def count_permissions(data, permission_projects):

    for entry in data:
        project = entry.get('project', 'Unknown')  
        if 'clusterRole' in entry and 'rules' in entry['clusterRole']:
            rules = entry['clusterRole']['rules']
            for rule in rules:
                for resources, operations in rule.items():
    
                    resource_list = resources.split(',')
                    for resource in resource_list:
                      
                        for operation in operations:
                            permission = f"{resource.strip()}:{operation.strip()}"
                            permission_projects[permission].add(project)  
def process_directory(directory_path):
    permission_projects = defaultdict(set)
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                data = load_data(file_path)
                count_permissions(data, permission_projects)

    permission_project_count = {permission: len(projects) for permission, projects in permission_projects.items()}

    sorted_permissions = sorted(permission_project_count.items(), key=lambda x: x[1], reverse=True)
    return sorted_permissions, len(permission_project_count)

def main():
    directory_path = 'dir'  
    output_file_path = 'log2_project.txt'  
    sorted_permissions, total_permissions = process_directory(directory_path)
    
    with open(output_file_path, 'w') as output_file:
        output_file.write(f"Total number of unique permissions: {total_permissions}\n")
        for permission, count in sorted_permissions:
            output_file.write(f"{permission}: {count}\n")

if __name__ == "__main__":
    main()
