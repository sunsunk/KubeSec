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

def create_project(project_name):
    url = "http://localhost:8080/api/v1/project"
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": "odt_tcPxgVCu19r3OL7ytm2vveMas89eaSOZ"  # 替换为你的有效 API 密钥
    }
    data = {
        "name": project_name,
        "version": 'latest'
    }
    response = requests.put(url, headers=headers, json=data)
    if response.status_code == 201:
        created.append(project_name)
        print("Project created successfully.")
    else:
        print(f"Failed to create project. Error: {response.text}")
        failed_create.append(project_name)

def create_projects(directory_path, project_version="latest"):
    projects = find_project(directory_path)
    for project in projects:
        create_project(project, project_version)
    print(f"Succeeded: {len(created)}")
    print(f"Failed: {failed_create}")

# # 示例用法
# directory_path = "../../dateset"
# create_projects(directory_path)
