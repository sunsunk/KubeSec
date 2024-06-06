import json
import os
import glob

def find_item_by_bom_ref(vulner_path, bom_ref):
    with open(vulner_path) as file:
        json_data = json.load(file)
        components = json_data['components']
        matching_items = []
        for item in components:
            if item['bom-ref'] == bom_ref:
                del item['bom-ref']
                matching_items.append(item)
        return matching_items

def process_vulnerabilities(vulner_path):
    finall_vulner = []
    with open(vulner_path) as file:
        json_data = json.load(file)
        if "vulnerabilities" in json_data:
            vulnerabilities = json_data["vulnerabilities"]
            project_name = json_data['metadata']['component']['name']
            for vulner in vulnerabilities:
                del vulner['bom-ref']
                affects_items = []
                affects = vulner['affects']
                for affect in affects:
                    item = find_item_by_bom_ref(vulner_path, affect['ref'])
                    if item == None:
                        print("match failed!")
                    affects_items.append(item)
                del vulner['affects']
                vulner['affect_components'] = affects_items
                finall_vulner.append(vulner)
       
            # 确保输出路径的目录存在
            output_dir = f'./target/tpc/vulners-reports/'
            os.makedirs(output_dir, exist_ok=True)
            # 写入结果到新的JSON文件
            with open(f'{output_dir}{project_name}_report.json', 'w') as file:
                json.dump(finall_vulner, file, ensure_ascii=False, indent=4)


def process_folder(folder_path):
    # 获取指定文件夹下的所有文件名
    file_paths = glob.glob(os.path.join(folder_path, '*'))
    for file_path in file_paths:
        if os.path.isfile(file_path):
            print(file_path)
            process_vulnerabilities(file_path)

# # 指定文件夹路径
# folder_path = '../../target/vulners-boms/'

# # 处理文件夹中的所有文件
# process_folder(folder_path)
