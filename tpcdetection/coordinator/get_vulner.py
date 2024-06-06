import requests

def download_vulnerability_report(project_id,out_path):
    url = f'http://localhost:8080/api/v1/bom/cyclonedx/project/{project_id}'
    params = {
        'format': 'json',
        'variant': 'withVulnerabilities',
        'download': 'true'
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br',
        'Authorization': 'your-bear-token',
        'Referer': f'http://localhost:8080/projects/{project_id}/components',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
    }

    response = requests.get(url, params=params, headers=headers)

    if response.status_code == 200:
        file_name = out_path  
        with open(file_name, "wb") as file:
            file.write(response.content)
        return file_name
    else:
        print(f"Request failed with status code: {response.status_code}")
        return None
project_id = '7cd907ba-114a-4db9-874b-e8ee883b595f'
file_name= download_vulnerability_report(project_id,"1.json")
if file_name:
    print(f"File downloaded and saved as {file_name}")
else:
    print("Failed to download the file.")