from tpcdetection.coordinator import get_boms as gb
from tpcdetection.coordinator import create_project as cp
from tpcdetection.coordinator import detect as dt
import os
import sys
import time 
directory_path = "./dateset"
output_directory = "./target"


gb.process_projects(directory_path, output_directory)
cp.create_project(directory_path)

projects_dict = dt.get_projects()
sys.stdout = open(f'{output_directory}/logs/download_vulner.log', 'w')
#遍历字典的值
for project_name,project_uuid in projects_dict.items():
    dt.upload_bom(project_name,project_uuid)
    print("Waiting 5 seconds...")
    time.sleep(5)

for project_name,project_uuid in projects_dict.items():
    dt.download_vulnerability_report(project_name,project_uuid,f"{output_directory}/vulners-boms/{project_name}.vulner.json")
# print(dt.error_download)