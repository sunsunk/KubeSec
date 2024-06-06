import requests
import json
import os
created = []
failed_create = []

def find_project(directory):
    project_name = []
    for entry in os.scandir(directory):
        if entry.is_dir():
            subdir = entry.name
            project_name.append(subdir)
    return project_name


def create_project(project_name, project_version):
    url = "http://localhost:8080/api/v1/project"
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": "your-api-key"  
    }
    data = {
        "name": project_name,
        "version": project_version
    }
    response = requests.put(url, headers=headers, json=data)
    if response.status_code == 201:
        created.append(project_name)
        print("Project created successfully.")
    else:
        print(f"Failed to create project. Error: {response.text}")
        failed_create.append(project_name)
        
directory_path = "../cncf-project/graduated"
projects = find_project(directory_path)       
for project in projects:
    create_project(project,"latest")
print(f"succeed:{len(created)}")
print(f"failed create projects::{failed_create}")