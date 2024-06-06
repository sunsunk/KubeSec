import os
import sys
import time
import argparse
from tpcdetection.coordinator import get_boms as gb
from tpcdetection.coordinator import create_project as cp
from tpcdetection.coordinator import detect as dt
from tpcdetection.coordinator import analis as als
from privilegedetection import configlocator as ct
from privilegedetection import riskanalyzer as rr

def tpc(directory_path, output_directory):
    gb.process_projects(directory_path, output_directory)
    projects = dt.find_project(directory_path)
    print(projects)       
    for project in projects:
        cp.create_project(project)
    projects_dict = dt.get_projects()
    sys.stdout = open(f'{output_directory}/logs/download_vulner.log', 'w')
    for project_name, project_uuid in projects_dict.items():
        dt.upload_bom(project_name, project_uuid)
        print("Waiting 5 seconds...")
        time.sleep(5)
    for project_name, project_uuid in projects_dict.items():
        dt.download_vulnerability_report(project_name, project_uuid, f"{output_directory}/vulners-boms/{project_name}.vulner.json")
    folder_path = './target/tpc/vulners-boms/'
    als.process_folder(folder_path)

def rbac(directory_path):
    ct.loc(directory_path)
    file_path = './target/rbac/CLUSTEROLE_BINDING_INFO.json'
    rr.analyze(file_path, './target/rbac/permission_report.xlsx')
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some directories.')
    parser.add_argument('directory_path', type=str, help='Path to the dataset directory')

    args = parser.parse_args()
    output_directory = "./target/tpc"
    rbac(args.directory_path)
    tpc(args.directory_path, output_directory)

    