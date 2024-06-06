import os
import glob
import subprocess
import re
import chardet
import argparse
from privilegedetection.parse import Parse
helm_project = set()

def traverse_directory(directory):
    result_dict = {}
    for entry in os.scandir(directory):
        if entry.is_dir():
            subdir = entry.name
            yaml_files = find_yaml_files(os.path.join(directory, subdir))
            result_dict[subdir] = yaml_files
    return result_dict

def find_project(directory):
    project_name = []
    for entry in os.scandir(directory):
        if entry.is_dir():
            subdir = entry.name
            project_name.append(subdir)
    return project_name

def find_yaml_files(directory):
    yaml_files_ = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".yaml") or file.endswith(".yml"):
                yaml_files_.append(os.path.join(root, file))
    return yaml_files_

def find_values_yaml_directory(directory):
    for root, dirs, files in os.walk(directory):
        if "values.yaml" in files:
            values_yaml_directory = root
            print("values.yaml file found in directory:", values_yaml_directory)
            return values_yaml_directory

def generate_helm_output_to_yaml(p, values_file, output_file, helm_dir):
    helm_command = f"helm template my-release -f {values_file} {helm_dir}"
    try:
        output = subprocess.check_output(helm_command, shell=True, text=True)
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as file:

            content = output
            print(f"Helm output has been written to {output_file}")
            yaml_documents = re.split('---\n(?=# Source: )', content)
            
            yaml_files = {}  

            for index, document in enumerate(yaml_documents):
                match = re.search(r'# Source: (.+)', document)
                if match:
                    source = match.group(1)
                    if source not in yaml_files:
                        yaml_files[source] = document
                    else:
                        yaml_files[source] += "\n---\n" + document
            
            for source, yaml_content in yaml_files.items():
                output_file = os.path.basename(source)
                print(f'helm output {output_file}')
                output_file = helm_dir + output_file
                with open(output_file, 'w') as file:
                    file.write(yaml_content)
                print(f"YAML content for source {source} written to {output_file}")
                with open("./target/rbac/logs/rbac.log", "a") as file:
                    filename = source.split('/')[-1]
                    p.helm_process_file.append(filename)  
                    helm_project.add(filename)  
                    file.write(source + "\n")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while running Helm command: {e}")

def check_strings_in_file(strings, file_path):
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read()
            result = chardet.detect(raw_data)
            encoding = result['encoding']
        with open(file_path, 'r', encoding=encoding) as file:
            file_content = file.read()
            for string in strings:
                if string in file_content:
                    return True
    except Exception as e:
        print(e)
        return False


def replace_template_values(p, yaml_content, replacement):
    lines = yaml_content.split("\n")
    replaced_lines = []
    pattern = r"\{\{.*?\}\}"
    include_pattern = r"\{\{-\s*include.*?\}\}"
    for line in lines:
        if re.search(r"\{\{-\s*(end|if).*?\}\}", line):  
            continue
        elif re.search(include_pattern, line):  
            line = re.sub(pattern, "", line)  
        elif re.search(pattern, line):  
            if re.match(r"^\s*\{\{.*\}\}\s*$", line):  
                continue
            line = re.sub(pattern, replacement, line)
        
        if "{" in line or "}" in line:  
            continue
        
        replaced_lines.append(line)
    
    replaced_content = "\n".join(replaced_lines)
    print(f'post —— processing：{p.errorFile}')
    return replaced_content

def load_and_merge_yaml_files(p, file_pattern):
    merged_yaml = ""
    yaml_files = glob.glob(file_pattern)
    for file_path in yaml_files:
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                result = chardet.detect(raw_data)
                encoding = result['encoding']
            with open(file_path, 'r', encoding=encoding) as file:
                yaml_content = file.read()
                replaced_yaml = replace_template_values(p, yaml_content, "dynamic_parameters")
                merged_yaml += replaced_yaml + "\n---\n"  
        except Exception as e:
            print(e)
            return False
    return merged_yaml

def save_to_file(file_path, content):
    with open(file_path, 'rb') as f:
        raw_data = f.read()
        result = chardet.detect(raw_data)
        encoding = result['encoding']
    with open(file_path, 'w', encoding=encoding) as file:
        file.write(content)

def post_processing_helm(p, file_path):
    merged_yaml = load_and_merge_yaml_files(p, file_path)
    save_to_file(file_path, merged_yaml)
    p.helm_process_file.append(os.path.basename(file_path))

def loc(directory_path):

    strings = ['ServiceAccount', 'ClusterRole', 'ClusterRoleBinding', 'Role', 'RoleBinding', 'Deployment'] 
    projects = find_project(directory_path)

    for project in projects:
        print(project)
        p = Parse()
        yaml_files = []
        os.makedirs(os.path.dirname("./target/rbac/logs"), exist_ok=True)
        with open("./target/rbac/rbac.logs", "a") as file:
            file.write("\n" + project + ':' + "\n")
            file.write("helm :\n")
        helm = find_values_yaml_directory(directory_path + f'/{project}')    
        if helm:
            values_file_path = helm + '/values.yaml'
            os.makedirs(os.path.dirname("./target/rbac/logs"), exist_ok=True)
            output_ = "./target/rbac/logs/output.yaml"
            generate_helm_output_to_yaml(p, values_file_path, output_, helm + '/')

        yaml_files = find_yaml_files(directory_path + '/' + project)

        for yaml_file in yaml_files:
            flag = check_strings_in_file(strings, yaml_file)
            if flag:
                p.parse(project, yaml_file)

        with open("./target/rbac/logs/rbac.logs", "a") as file:
            file.write("\n" + project + ':' + "\n")
            file.write("missed yaml :\n")
            for item in p.errorFile:
                post_processing_helm(p, item)
                
                p.parse(project, yaml_file)
                _name = os.path.basename(item)
                
                if _name not in p.helm_process_file:
                    file.write(item + "\n")
                else:
                    p.errorFile.remove(item)
   
        p.relationMapping()
        print(p.helm_process_file)
        helm_project = set()    


