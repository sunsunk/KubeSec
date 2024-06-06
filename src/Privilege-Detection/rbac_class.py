import json
import os
from collections import defaultdict

def load_data(file_path):
    loaded_data = []
    with open(file_path, "r") as json_file:
        for line in json_file:
            data = json.loads(line)
            loaded_data.append(data)
    return loaded_data

def count_permissions(data, permission_count):
    for entry in data:
        if 'clusterRole' in entry and 'rules' in entry['clusterRole']:
            rules = entry['clusterRole']['rules']
            for rule in rules:
                for resources, operations in rule.items():
                    # 将资源按逗号分隔
                    resource_list = resources.split(',')
                    for resource in resource_list:
                        # 形成权限字符串并统计
                        for operation in operations:
                            permission = f"{resource}:{operation}"
                            permission_count[permission] += 1

def process_directory(directory_path):
    permission_count = defaultdict(int)
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                data = load_data(file_path)
                count_permissions(data, permission_count)

    sorted_permissions = sorted(permission_count.items(), key=lambda x: x[1], reverse=True)
    return sorted_permissions, len(permission_count)

def main():
    directory_path = 'dir'  
    output_file_path = 'log2.txt'  
    sorted_permissions, total_permissions = process_directory(directory_path)
    
    # 输出结果到文件
    with open(output_file_path, 'w') as output_file:
        output_file.write(f"Total number of unique permissions: {total_permissions}\n")
        for permission, count in sorted_permissions:
            output_file.write(f"{permission}: {count}\n")

if __name__ == "__main__":
    main()
