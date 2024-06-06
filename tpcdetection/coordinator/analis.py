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

folder_path = '../vulners-boms/graduated/'


file_names = []
for file_path in glob.glob(os.path.join(folder_path, '*')):
    if os.path.isfile(file_path):
        file_names.append(os.path.basename(file_path))


for file_name in file_names:

    vulner_path = f'../vulners-boms/graduated/{file_name}'

    project_name = None
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
                    item = find_item_by_bom_ref(vulner_path,affect['ref'])
                    if item == None:
                        print("match failed!")
                    affects_items.append(item)
                    del vulner['affects']
                    vulner['affect_components'] = affects_items
                finall_vulner.append(vulner)
       
            with open(f'../vulner-reports/graduated/{project_name}_report.json', 'w') as file:
                for item in finall_vulner:
                    json.dump(item, file, ensure_ascii=False, indent=0)
                    file.write('\n')  