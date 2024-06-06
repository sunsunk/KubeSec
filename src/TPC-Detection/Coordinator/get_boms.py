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
class_name = 'graduated'
directory_path = f"../cncf-project/{class_name}/"
outputdir = f"../boms/{class_name}/"
projects = find_project(directory_path)
print(projects)

sys.stdout = open('../logs/getboms.txt', 'w')
print(f"All projects : {projects}")
for project in projects:
    print(f"\nProject:{project}")
    bom = find_go_mod_files(directory_path+project)
    if bom:
        print(bom)
        outputfile = outputdir+f"{project}.bom.json"
        print(f"go.mod path: {outputfile}")
        modified_bom = bom.rsplit("/", 1)[0]
        generate_bom(project,outputfile,modified_bom)
    else:
        error_project.append(project)                                                                                                                                                                                                                            
print(f"Error projects:{error_project}")
print(len(error_project))