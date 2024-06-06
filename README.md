## Towards Understanding the Takeover Risks Introduced by Third-Party Applications in Kubernetes Ecosystem

## Dataset



## KubeSec

  KubeSec is used to fully automate the identification of dangerous authorizations and TPC vulnerabilities in TPA.
  
  KubeSec is developed in python and go.























#### Main function of each module
- Privilege_detection:
  - config_lcator.py
  - config_fetcher.go （Need to run on Kubernetes  master node）
- TPA collection: 
  - craw.py
- TPC detection : 
  - analis.py 
### Data structure in Privilege_detection
Key data structures
```
ClusterRole{
    kind:' ',
    name:' ',
    rules:[
        {
            apigroup:' ',
            resources_verbs:[{res1:[verb1,verb2,...]},{res1:[verb1,verb2,...]}]
    }
    ,...
    ]
}
Role{
    kind:' ',
    name:' ',
    namespace:' ',
    rules:[
        {
            apigroup:' ',
            resources_verbs:[{res1:[verb1,verb2,...]},{res1:[verb1,verb2,...]}]
    }
    ,...
    ]
}
Rolebinding{
    name:' ',
    namespace:' ',
    subject:[{kind:' ',name:' ',namespace:' '},...],
    roleRef_name:' ',
  # Role:{}
}
ClusterRolebinding{
    name:' ',
    namespace:' ',
    subject:[{kind:' ',name:' ',namespace:' '},...],
    roleRef_name:' '
  # ClusterRole{}
}
```
