import requests

def get_projects():
    url = "http://localhost:8080/api/v1/project"
    headers = {
        "X-Api-Key": "odt_tcPxgVCu19r3OL7ytm2vveMas89eaSOZ"  # 替换为你的有效 API 密钥
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        projects = response.json()
        project_dict = {}
        for project in projects:
            project_uuid = project["uuid"]
            project_name = project["name"]
            project_dict[project_name] = project_uuid
        return project_dict
    else:
        print(f"Failed to retrieve projects. Error: {response.text}")
        return {}

def delete_project(project_uuid):
    url = f"http://localhost:8080/api/v1/project/{project_uuid}"
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": "odt_tcPxgVCu19r3OL7ytm2vveMas89eaSOZ"  
    }
    response = requests.delete(url, headers=headers)
    if response.status_code == 204:
        print("Project deleted successfully.")
    else:
        print(f"Failed to delete project. Error: {response.text}")

projects_dict = get_projects()

for project_name,project_uuid in projects_dict.items():
    delete_project(project_uuid)