import os
import subprocess
import sys

error_project = []

def find_project(directory):
    project_name = []
    for entry in os.scandir(directory):
        if entry.is_dir():
            subdir = entry.name
            project_name.append(subdir)
    return project_name

def generate_bom(project, output_path, project_path):
    print(f"Processing {project}....")
    command = f"cyclonedx-gomod mod -json -output {output_path} {project_path}"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)

    if process.returncode == 0:
        print(f"{project} BOM generation completed successfully.")
        with open(output_path, 'a') as file:
            file.write(process.stdout)
            file.write("\n")
    else:
        print(f"Failed to generate {project} BOM. Error: {process.stderr}")

def find_go_mod_files(directory):
    for root, dirs, files in os.walk(directory):
        if "go.mod" in files:
            go_mod_path = os.path.join(root, "go.mod")
            return go_mod_path
    return None

def process_projects(directory_path, output_directory):

    outputdir = os.path.join(output_directory, "sboms")
    
    if not os.path.exists(outputdir):
        os.makedirs(outputdir)
    
    projects = find_project(directory_path)
    print(projects)

    log_directory = os.path.join(output_directory, "logs")
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)
    log_file_path = os.path.join(log_directory, "sboms.log")

    sys.stdout = open(log_file_path, 'w')

    for project in projects:
        bom = find_go_mod_files(os.path.join(directory_path, project))
        if bom:
            print(bom)
            outputfile = os.path.join(outputdir, f"{project}.bom.json")
            print(f"go.mod path: {outputfile}")
            modified_bom = os.path.dirname(bom)
            generate_bom(project, outputfile, modified_bom)
        else:
            error_project.append(project)


# # 示例调用
# directory_path = "../../dateset"
# output_directory = "../../target"


# process_projects(directory_path, output_directory)
