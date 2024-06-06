import requests

def get_projects():
    url = "http://localhost:8080/api/v1/project"
    headers = {
        "X-Api-Key": "your-api-key"  
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

print(get_projects())