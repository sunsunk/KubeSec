## KubeSec: Automatic detection of takeover risks introduced by Third-Party Apps in the K8s ecosystem

## KubeSec

  KubeSec is used to  comprehensively automate the identification of takeover risk of TPAs.

### Install
 KubeSec is developed in python and go. 

At the same time, It integrated two advanced TPC analysis tools.(CycloneDX、Dependency-Track).

Before you use kubesec, make sure you have enabled these tow tools.

1.  **Install CycloneDX**  
```go
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
```

2. **deploloy Dependency-Track**
   Deploy Dependency-Track via Docker,We provide the corresponding docker-compose.yaml for your quick deployment
  
    ```yaml
    version: '3.7'
    volumes:
      dependency-track:
      postgres-volume:
    
    services:
      db:
        image: postgres
        environment:
          - POSTGRES_USER=dtrack_postgres_user
          - POSTGRES_PASSWORD=dtrack_postgres_passwd
          - POSTGRES_DB=dtrack
        volumes:
          - 'postgres-volume:/var/lib/postgresql/data'
        restart: always
    
      dtrack-apiserver:
        image: dependencytrack/apiserver
        depends_on:
          - db
        environment:
        # Database Properties
        - ALPINE_DATABASE_MODE=external
        - ALPINE_DATABASE_URL=jdbc:postgresql://db:5432/dtrack
        - ALPINE_DATABASE_DRIVER=org.postgresql.Driver
        - ALPINE_DATABASE_USERNAME=dtrack_postgres_user
        - ALPINE_DATABASE_PASSWORD=dtrack_postgres_passwd
    
        deploy:
          resources:
            limits:
              memory: 12288m
            reservations:
              memory: 8192m
          restart_policy:
            condition: on-failure
        ports:
          - '8288:8080'
        volumes:
          - 'dependency-track:/data'
        restart: unless-stopped
    
      dtrack-frontend:
        image: dependencytrack/frontend
        depends_on:
          - dtrack-apiserver
        environment:
      # Note here, change the URL to the dtrack-apiserver address
          - API_BASE_URL=http://10.1.1.70:8288
        ports:
          - "8188:8080"
        restart: unless-stopped
    ```
   



## Usage

run command:

```
python kubesec.py $TPAs_Directory
```

All detection results will be output to the target directory.

***Notice：***

- The permission detection results are stored in /target/rbac/permission_report.xlsx
- The detection results of each TPS are in the /target/tpc/vulners-reports directory

- If you want to use configfetcher alone, run the command `go run configfetcher.go`  on the k8s controller node.

## Test

run command:

```python
python kubesec.py test-sources
```

The *test-sources* directory contains three TPAs for testing.The rbac-eg and tpc-eg in the target directory store the expected test results of kubesec, which can be used to detect whether kubesec is working properly.













