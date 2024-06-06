import requests
def upload_bom(project_name,project_uuid):
    url = 'http://localhost:8080/api/v1/bom'
    headers = {
        "X-Api-Key":"your-api-key",
        'Accept': 'application/json, text/plain, */*',
        'Referer': f'http://localhost:8080/projects/{project_uuid}/components'
    }

    files = {
        'project': (None, f'{project_uuid}'),
        'bom': (f'{project_name}.bom.json', open(f'../boms/incubating/{project_name}.bom.json', 'rb'), 'application/json')
    }

    response = requests.post(url, headers=headers, files=files)
    print(response.status_code)
    # print(response.json())
upload_bom("cert-manager-master","5a203693-c176-43a2-b425-78bce789baa4")
