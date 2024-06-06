import requests

url = "http://localhost:8080/api/v1/bom/cyclonedx/project/57eba1a3-1a2e-437c-9e5b-2ed457c5f7b6"
params = {
    "format": "json",
    "variant": "vdr",
    "download": "true"
}
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    "Accept-Encoding": "gzip, deflate, br",
    "Authorization": "your-bear-token",
    "Connection": "close",
    "Referer": "http://localhost:8080/projects/57eba1a3-1a2e-437c-9e5b-2ed457c5f7b6/findings",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin"
}

response = requests.get(url, params=params, headers=headers)

if response.status_code == 200:
    file_name = "bom.json"  # 文件保存的名称
    with open(file_name, "wb") as file:
        file.write(response.content)
    print(f"File downloaded and saved as {file_name}")
else:
    print(f"Request failed with status code: {response.status_code}")