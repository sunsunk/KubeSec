import requests
import sys
import time
import os

error_download = []

def find_go_mod_files(directory):
    for root, dirs, files in os.walk(directory):
        if "go.mod" in files:
            go_mod_path = os.path.join(root, "go.mod")
            return go_mod_path
    return None

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

def delete_project(project_uuid):
    url = f"http://localhost:8080/api/v1/project/{project_uuid}"
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": "your-api-key"  
    }
    response = requests.delete(url, headers=headers)
    if response.status_code == 204:
        print("Project deleted successfully.")
    else:
        print(f"Failed to delete project. Error: {response.text}")

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
        print("Project created successfully.")
    else:
        print(f"Failed to create project. Error: {response.text}")

def find_project(directory):
    project_name = []
    for entry in os.scandir(directory):
        if entry.is_dir():
            subdir = entry.name
            project_name.append(subdir)
    return project_name

def upload_bom(project_name,project_uuid):
    url = 'http://localhost:8080/api/v1/bom'
    headers = {
        "X-Api-Key":"your-api-key",
        'Accept': 'application/json, text/plain, */*',
        'Referer': f'http://localhost:8080/projects/{project_uuid}/components'
    }
    file_path = f"../boms/graduated/{project_name}.bom.json"
    print(file_path)
    if os.path.exists(file_path):
        files = {
            'project': (None, f'{project_uuid}'),
            'bom': (f'{project_name}.bom.json', open(file_path, 'rb'), 'application/json')
        }
        response = requests.post(url, headers=headers, files=files)
        print(response.status_code)
        print(response)
    else:
        # 文件不存在，将路径记录到 error.txt 文件中
        with open("error.txt", "a") as error_file:
            error_file.write(f"File not found: {file_path}\n")
'''
获取漏洞报告
'''
def download_vulnerability_report(project_name,project_id,out_path):
    url = f'http://localhost:8080/api/v1/bom/cyclonedx/project/{project_id}'
    params = {
        'format': 'json',
        'variant': 'withVulnerabilities',
        'download': 'true'
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br',
        "X-Api-Key":"your-api-key",
        'Referer': f'http://localhost:8080/projects/{project_id}/components',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
    }

    response = requests.get(url, params=params, headers=headers)

    if response.status_code == 200:
        file_name = out_path  
        with open(file_name, "wb") as file:
            file.write(response.content)
        print(f"Download succeed,output to {out_path}")
        return file_name
    else:
        error_download.append(project_name)
        print(f"Request failed with status code: {response.status_code}")
        return None



projects_dict = get_projects()

sys.stdout = open('../logs/download_vulner.txt', 'w')

for project_name,project_uuid in projects_dict.items():
    upload_bom(project_name,project_uuid)
    print("Waiting 5 seconds...")
    time.sleep(5)

for project_name,project_uuid in projects_dict.items():
    download_vulnerability_report(project_name,project_uuid,f"../vulners-boms/{project_name}.vulner.json")
print(error_download)