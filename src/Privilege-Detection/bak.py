import os
import glob
import subprocess
import re
import chardet
import argparse
from parse import Parse

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
        # print(f'helm output:{output}')
        with open(output_file, "w") as file:
            # file.write(output)
            content = output
            print(f"Helm output has been written to {output_file}")
            yaml_documents = re.split('---\n(?=# Source: )', content)
            
            yaml_files = {}  # 用于保存每个 source 对应的 YAML 内容
            
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
                with open("error_logs.txt", "a") as file:
                    filename = source.split('/')[-1]
                    p.helm_process_file.append(filename)  # 记录该对象被 Helm 处理的文件
                    helm_project.add(filename)  # run 函数记录 Helm 处理
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

# 替换heml模板引擎值
def replace_template_values(p, yaml_content, replacement):
    lines = yaml_content.split("\n")
    replaced_lines = []
    pattern = r"\{\{.*?\}\}"
    include_pattern = r"\{\{-\s*include.*?\}\}"
    for line in lines:
        if re.search(r"\{\{-\s*(end|if).*?\}\}", line):  # 匹配到 "{{- end }}" 或类似 "{{- if .Values.controller.enabled }}"
            continue
        elif re.search(include_pattern, line):  # 匹配到 "{{- include }}" 形式的内容
            line = re.sub(pattern, "", line)  # 删除 "{{ }}" 部分内容
        elif re.search(pattern, line):  # 匹配到其他 "{{ ... }}" 形式的内容
            if re.match(r"^\s*\{\{.*\}\}\s*$", line):  # 匹配到只有 "{{ ... }}" 的行
                continue
            line = re.sub(pattern, replacement, line)
        
        if "{" in line or "}" in line:  # 检查行中是否还存在 "{" 或 "}"
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
                merged_yaml += replaced_yaml + "\n---\n"  # 添加分隔符
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

# helm 后处理
def post_processing_helm(p, file_path):
    merged_yaml = load_and_merge_yaml_files(p, file_path)
    # 将合并后的 YAML 内容保存回原始文件
    save_to_file(file_path, merged_yaml)
    print(f"已将合并后的 YAML 内容保存到文件: {file_path}")
    p.helm_process_file.append(os.path.basename(file_path))

def main():
    global helm_project

    # 使用 argparse 解析命令行参数
    parser = argparse.ArgumentParser(description='Process some directories.')
    parser.add_argument('directory_path', type=str, help='Path to the directory containing projects')
    args = parser.parse_args()
    directory_path = args.directory_path

    strings = ['ServiceAccount', 'ClusterRole', 'ClusterRoleBinding', 'Role', 'RoleBinding', 'Deployment'] 
    projects = find_project(directory_path)

    for project in projects:
        print(project)
        p = Parse()
        yaml_files = []
        with open("error_logs.txt", "a") as file:
            file.write("\n" + project + ':' + "\n")
            file.write("helm :\n")
        helm = find_values_yaml_directory(directory_path + f'/{project}')    
        # 处理helm引擎 
        if helm:
            values_file_path = helm + '/values.yaml'
            # 替换为您要输出的 YAML 文件路径
            output_ = "./output.yaml"
            generate_helm_output_to_yaml(p, values_file_path, output_, helm + '/')

        yaml_files = find_yaml_files(directory_path + '/' + project)

        for yaml_file in yaml_files:
            flag = check_strings_in_file(strings, yaml_file)
            if flag:
                p.parse(project, yaml_file)

        with open("error_logs.txt", "a") as file:
            file.write("\n" + project + ':' + "\n")
            file.write("missed yaml :\n")
            for item in p.errorFile:
                # 后处理
                post_processing_helm(p, item)
                # 再处理
                p.parse(project, yaml_file)
                _name = os.path.basename(item)
                # 筛选掉 helm 模板引擎处理过的文件，不作日志记录,helm_process_file记录helm模板处理或helm后处理
                if _name not in p.helm_process_file:
                    file.write(item + "\n")
                else:
                    p.errorFile.remove(item)

        # RBAC 关系映射    
        p.relationMapping()
        print(p.helm_process_file)
        helm_project = set()    

if __name__ == "__main__":
    main()
