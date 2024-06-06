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
