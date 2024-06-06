import yaml
import json
import subprocess
import re 
import os

class Parse:
    def __init__(self):
        self.clusterRole = []
        self.role = []
        self.clusterRoleBinding = []
        self.roleBinding = [] 
        self.errorFile = []  
        self.pod = []
        self.helm_process_file = []
        
    def getRItems(self,doc):
        r_item= {}
        kind = doc.get('kind')
        metadata = doc.get('metadata', {})
        name = metadata.get('name')
        labels = metadata.get('labels', {})
        class_value = labels.get('class')
        namespace = metadata.get('namespace')
    
        r_item['kind'] = kind
        r_item['name'] = name
        r_item['label_class'] = class_value
        if namespace:
            r_item['namespace'] = namespace
        rules = []
        rules_ = doc.get('rules', [])
        for rule in rules_:
            api_groups = rule.get('apiGroups', [])
            resources = rule.get('resources', [])
            resources = ','.join(resources)
            verbs = rule.get('verbs', [])

            rule_item = {}
            rule_item[resources] = verbs
            rules.append(rule_item)      
        r_item['rules'] = rules
        return r_item
    
    def getBindingItems(sef,doc,project):
        b_item = {}

        kind = doc.get('kind')
        metadata = doc.get('metadata', {})
        name = metadata.get('name')
        labels = metadata.get('labels', {})
        class_value = labels.get('class')
        namespace = metadata.get('namespace')
        subjects = doc.get('subjects', [])
        b_item['project'] = project
        b_item['kind'] = kind
        b_item['name'] = name
        b_item['labels_class'] = labels
        b_item['namespace'] = namespace
        b_item['subject'] = subjects
        b_item['roleRef'] = doc.get('roleRef')
        return b_item

    def parseServiceAccount(self,doc):
        metadata = doc.get('metadata', {})
        name = metadata.get('name')
        namespace = metadata.get('namespace') 

    def parseClusterRole(self,doc,file_path):
        if self.clusterRole == None:
            self.clusterRole = []
        clusterRole_item =  self.getRItems(doc)
        clusterRole_item['file'] = file_path
        self.clusterRole.append(clusterRole_item)
    def parseClusterRoleBinding(self,doc,project):
        if self.clusterRoleBinding == None:
            self.clusterRoleBinding = []
        clusterRoleBinding_item =  self.getBindingItems(doc,project)
        if clusterRoleBinding_item not in self.clusterRoleBinding:
            self.clusterRoleBinding.append(clusterRoleBinding_item)
    def parseRoleBinding(self,doc,project):
        if self.roleBinding == None:
            self.roleBinding = []
        roleBinding_item =  self.getBindingItems(doc,project)
        if roleBinding_item not in self.roleBinding:
            self.roleBinding.append(roleBinding_item) 
    def parseRole(self,doc):
        if self.role == None:
            self.role = []
        role_item =  self.getRItems(doc)
        self.role.append(role_item)
    def parsePod(self,doc):
        kind = doc.get('kind')
        metadata = doc.get('metadata')
        name = metadata.get('name') if metadata else None
        namespace = metadata.get('namespace') if metadata else None
        spec = doc.get('spec')
        sa_name = spec['template']['spec'].get('serviceAccountName') if spec else None
        pod_item = {'pod_name':name,'namespace':namespace,'sa_name':sa_name}
        self.pod.append(pod_item)
    def parseDaemonset(self,doc):
        kind = doc.get('kind')
        metadata = doc.get('metadata')
        name = metadata.get('name') if metadata else None
        namespace = metadata.get('namespace') if metadata else None
        spec = doc.get('spec')
        sa_name = spec['template']['spec'].get('serviceAccountName') if spec else None
        pod_item = {'pod_name':name,'namespace':namespace,'sa_name':sa_name}
        self.pod.append(pod_item)
    def relationMapping(self):
        file_path= './target/rbac/CLUSTEROLE_BINDING_INFO.json'
        with open(file_path, 'a') as json_file:
            for cltR in self.clusterRoleBinding:
                roleR = cltR['roleRef']
                for r in self.clusterRole:
                    if 'name' in roleR and 'name' in r and roleR['name'] == r['name']:  
                        cltR['clusterRole'] = r

                for p in self.pod:
                    for subject in cltR['subject']:
                        if isinstance(subject, dict):
                            if 'sa_name' in p and 'name' in subject and p['sa_name'] == subject['name']:
                                cltR['Pod'] = p
                json_file.write(json.dumps(cltR) + '\n')
        file_path= './target/rbac/ROLE_BINDING_INFO.json'
        with open(file_path, 'a') as file_rb:   
   
            for rb in self.roleBinding:
                roleR = rb['roleRef']
                for r in self.role:

                    if roleR is not None:
                        if 'name' in roleR and 'name' in r and roleR['name'] == r['name']: 
                            rb['role'] = r
                for p in self.pod:
                    for subject in rb['subject']:
                        if 'sa_name' in p and 'name' in subject and p['sa_name'] == subject['name']:
                            rb['Pod'] = p
           
                file_rb.write(json.dumps(rb) + '\n')
    def printinfo(self):
        print("Role")
        for item in self.role:
            print(item)
        print("clusterRoleBinding：")
        for item in self.clusterRoleBinding:
            print(item)
        print("roleBinding：")
        for item in self.roleBinding:
            print(item)
        print("clisterRole：")
        for item in self.clusterRole:
            print(item)

        print("errorfile")
        print(self.errorFile)

    def parse(self,project,file_path): 

        with open(file_path, 'r') as file:
            try:
                yaml_documents = yaml.safe_load_all(file)
        
                for doc in yaml_documents:
                    kind = doc.get('kind')
                    if kind == 'ClusterRole':
                        self.parseClusterRole(doc,file_path)
                    elif kind == 'Role':
                        self.parseRole(doc)
                    elif kind == 'ClusterRoleBinding':
                        self.parseClusterRoleBinding(doc,project)
                    elif kind == 'RoleBinding':
                        self.parseRoleBinding(doc,project)
                    elif kind == 'Deployment':
                        self.parsePod(doc)
                    elif kind == 'Daemonset':
                        self.parseDaemonset(doc)
            except Exception as e:
                self.errorFile.append(file_path)



