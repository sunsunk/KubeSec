import json
project  = set()
loaded_data = []

def check_rules(rules, data):
    flag = False
    for item in data:
        for rule_key, rule_values in rules.items():
            for data_key, data_value in item.items():
                data_keys = data_key.split(',')
                if rule_key in data_keys:
                    if ',' in data_value:
                        # 多个字符串，分别比较
                        data_values = data_value.split(',')
                        if any(set(rule_values) & set(val.strip()) for val in data_values):
                            flag = True
                            return flag
                    else:
                        # 单个字符串，直接比较
                        if set(rule_values) & set(data_value):
                            flag = True
                            return flag
    return flag
class_name = 'CLUSTEROLE_BINDING_INFO'
file_path = class_name+'.json'
# file_path = 'test.json'
with open(file_path, "r") as json_file:
    for line in json_file:
        data = json.loads(line)
        loaded_data.append(data)

# rules = {'pods':['create','delete'],'secrets':['list'],'*':['list','create','delete']}
rules = {'*':['list']}
# rules = {'secrets':['list']}
# rules = {'pods':['create']}
# rules = {'nodes':['patch']}
file_path = 'other_cR_' + class_name+'.json'

for data in loaded_data:
    if 'clusterRole' in data:
        r_rules = (data['clusterRole']['rules'])
        # print(r_rules)
        flag = check_rules(rules,r_rules)

        if flag:
            with open(file_path, 'a') as file_rb: 
                file_rb.write(json.dumps(data) + '\n')
