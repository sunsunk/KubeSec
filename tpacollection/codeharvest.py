import requests
from bs4 import BeautifulSoup
import zipfile
import tempfile
import json
count = 0
error_filelist = []
error_urls = []

def download(url):
    try:
        data = requests.get(url).content  
    except Exception as e:
        error_urls.append(url)
    _tmp_file = tempfile.TemporaryFile()  
    print(_tmp_file)
    
    try:
        _tmp_file.write(data)  
    except Exception as e:
        
        data = requests.get(url).content  
        _tmp_file.write(data)  

 
    zf = zipfile.ZipFile(_tmp_file, mode='r')
    for names in zf.namelist():
        try:
            f = zf.extract(names, 'sourcecode')  
        except Exception as e:
            error_filelist.append(names)
            
    zf.close()
def get_CNCF_Projects_SandBox(url):

 
    response = requests.get(url)
    content = response.content
    project_urls = []

    soup = BeautifulSoup(content, "html.parser")


    project_list = soup.find_all("div", class_="project-item has-animation-scale-2")
    

    for project in project_list:
        link = project.find("a", class_="project-item__link")
        if link:
            project_url = link["href"]
            project_urls.append(project_url)
    return project_urls
def get_CNCF_Projects_Graduated(url):
    response = requests.get(url)
    html_content = response.text

   
    soup = BeautifulSoup(html_content, 'html.parser')

    
    div_element = soup.find('div', class_='projects-archive columns-five')

    
    href_list = []

   
    a_tags = div_element.find_all('a')

   
    for a in a_tags:
        
        href = a.get('href')

       
        href_list.append(href)

   
    for href in href_list:
        print(href)

  
    print("Total links:", len(href_list))
    return href_list
def get_CNCF_Projects_Incubating(url):
    response = requests.get(url)
    html_content = response.text

   
    soup = BeautifulSoup(html_content, 'html.parser')

  
    div_elements = soup.find_all('div', class_='projects-archive columns-five')

    href_list = []


    if len(div_elements) > 1:
        div_element = div_elements[1] 
       
        a_tags = div_element.find_all('a')

      
        for a in a_tags:         
            href = a.get('href')      
            href_list.append(href)
        for href in href_list:
            print(href)
        print("Total links:", len(href_list))
    
    return href_list
def get_Github_Url(url):
    response = requests.get(url)
    content = response.content
    soup = BeautifulSoup(content, "html.parser")

    div_list = soup.find_all("div", class_="projects-single-box__icons")
    for div in div_list:
        link = div.find("a")
        if link:
            href = link.get("href")
            return href
def find_key(json_data, target_key):
    for key, value in json_data.items():
        if key == target_key:
            return value
        elif isinstance(value, dict):
            result = find_key(value, target_key)
            if result is not None:
                return result
    return None
def getDownloadUrl(url):
    print(f'Downloading.......{url}')
    global count
    count = count  + 1
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        script_elements = soup.find_all('script')

        for script in script_elements:
            if script.get('type') == 'application/json':
                json_data = json.loads(script.string)
                zipball_url = find_key(json_data, 'zipballUrl')

                if zipball_url:
                    print("Found zipballUrl:", zipball_url)
                    return "https://github.com" + zipball_url
        

urls = [
    "https://www.cncf.io/sandbox-projects/",
    "https://www.cncf.io/projects/"
]

for url in urls:
    c_urls = get_CNCF_Projects_SandBox(url)
    for c_url in c_urls:
        github_url = get_Github_Url(c_url)
        d_url = getDownloadUrl(github_url)
        download(d_url)