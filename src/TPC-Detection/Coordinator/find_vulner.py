import json

def find_item_by_bom_ref(vulner_path, bom_ref):
    with open(vulner_path) as file:
        json_data = json.load(file)
        components = json_data['components']
        matching_items = []
        for item in components:
            if item['bom-ref'] == bom_ref:
                
                matching_items.append(item)
        return matching_items

# 调用函数并打印匹配的结果
vulner_path = '../vulners/aeraki-master.vulner.json'
bom_ref = 'db26d2b9-275d-412e-a009-f1d62d7b3d0d'
matching_items = find_item_by_bom_ref(vulner_path, bom_ref)
for item in matching_items:
    print(item)