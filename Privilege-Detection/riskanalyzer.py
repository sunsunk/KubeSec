import json
import pandas as pd

def check_rules(risk_rule, data):
    for item in data:
        for rule_key, rule_values in risk_rule.items():
            for data_key, data_value in item.items():
                data_keys = data_key.split(',')
                if rule_key in data_keys:
                    if isinstance(data_value, list):
                        if any(set(rule_values) & {val.strip() for val in data_value}):
                            return True
                    else:
                        data_values = data_value.split(',')
                        if any(set(rule_values) & {val.strip() for val in data_values}):
                            return True
    return False

def load_data(file_path):
    loaded_data = []
    with open(file_path, "r") as json_file:
        for line in json_file:
            data = json.loads(line)
            loaded_data.append(data)
    return loaded_data

def generate_risk_rules(permission_list):
    risk_rules = []
    for level in permission_list:
        for rule in level:
            action, resource = rule[:2]
            risk_rules.append({resource: [action]})
    return risk_rules

def count_risk_rule_matches(data, risk_rules):
    rule_counts = {json.dumps(rule): set() for rule in risk_rules}
    for item in data:
        project_name = item.get('project')
        r_rules = item.get('clusterRole', {}).get('rules', [])
        for risk_rule in risk_rules:
            if check_rules(risk_rule, r_rules):
                rule_counts[json.dumps(risk_rule)].add(project_name)
    return rule_counts

def update_permission_list_with_counts(permission_list, rule_counts):
    updated_permission_list = []
    for level in permission_list:
        updated_level = []
        for rule in level:
            action, resource = rule[:2]
            rule_key = json.dumps({resource: [action]})
            count = len(rule_counts.get(rule_key, []))
            updated_rule = [action, resource, count]
            updated_level.append(updated_rule)
        updated_permission_list.append(updated_level)
    return updated_permission_list

def process_permission_data(file_path, permission_list):
    loaded_data = load_data(file_path)
    risk_rules = generate_risk_rules(permission_list)
    rule_counts = count_risk_rule_matches(loaded_data, risk_rules)
    updated_permission_list = update_permission_list_with_counts(permission_list, rule_counts)
    return updated_permission_list

def save_to_excel(permission_list, file_name):
    data = []
    for level_idx, level in enumerate(permission_list):
        for rule in level:
            action, resource, count = rule
            data.append({'Risk Level': level_idx + 1, 'Action': action, 'Resource': resource, 'Count': count})
    
    df = pd.DataFrame(data)
    df.to_excel(file_name, index=False)

def main():
    file_path = '../../target/CLUSTEROLE_BINDING_INFO.json'
    # 定义风险等级列表
    permission_list = [
        [
            ['*', '*'],  # 最大危险等级  任意操作  任意资源
        ],
        [
            ['*', 'secrets'],  # 第二级 任意操作  敏感资源 
            ['*',  'nodes'],
            ['*', 'clusterroles'],
            ['*', 'clusterrolebindings'],
            ['list', '*'],  # 第三级 敏感操作  任意资源 
            ['get', '*'],
            ['watch', '*'],
            ['patch', '*'],
            ['update', '*'],
        ],
        [
            ['list', 'secrets'],  # 第四级 敏感操作  敏感资源
            ['get', 'secrets'],
            ['watch', 'secrets'],
            ['patch', 'secrets'],
            ['update', 'secrets'],
            ['patch', 'nodes'],
            ['update', 'nodes'],

            ['list', 'clusterroles'],  
            ['get', 'clusterroles'],
            ['watch', 'clusterroles'],
            ['patch', 'clusterroles'],
            ['update', 'clusterroles'],

            ['list', 'clusterrolebindings'],  
            ['get', 'clusterrolebindings'],
            ['watch', 'clusterrolebindings'],
            ['patch', 'clusterrolebindings'],
            ['update', 'clusterrolebindings'],
            ['escalate', 'clusterrolebindings']
        ],
    ]

    updated_permission_list = process_permission_data(file_path, permission_list)

    save_to_excel(updated_permission_list, '../../target/permission_list.xlsx')

    for level in updated_permission_list:
        for rule in level:
            print(rule)

if __name__ == "__main__":
    main()
 