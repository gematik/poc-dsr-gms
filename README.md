# GMS - Geräte Management Service 

[!NOTE]
This software is a proof of concept and is not intended for production use. It will not be maintained or receive updates. Concepts from this project will be used in gematik specifications to standardize Zero Trust in Telematics Infrastructure. Developers are encouraged to use the implementation ideas in their own software.

**Part of the PoC Device Security Rating (DSR)**

This project uses Quarkus, the Supersonic Subatomic Java Framework.

If you want to learn more about Quarkus, please visit its website: https://quarkus.io/ .

## Configure
In script configure.sh: modify both openssl parameter "subj" in this script before run.
```shell script
./configure.sh
```
Set your values in src/main/resources/credentials/gematik-app-dev-apis-4644a13c06cb.json.


## Running the application in dev mode

You can run the GMS application in dev mode that enables live coding using:
```shell script
mvn compile quarkus:dev
```

## Packaging and running the application in prod mode

The application can be packaged using:
```shell script
mvn package
```
Maven -DskipTests is not necessary because we didn't publish unit tests for privacy reasons.
Tests require a lot of private data.

It produces the `quarkus-run.jar` file in the `target/quarkus-app/` directory.
Be aware that it’s not an _über-jar_ as the dependencies are copied into the `target/quarkus-app/lib/` directory.

### You can run the GMS application locally without live coding
First start Postgres DBMS: run gms-docker-dev/docker-compose_local-DEV.yml
```shell script
docker-compose --project-name gms -f gms-docker-dev/docker-compose_local-DEV.yml up -d
```

```shell script
java -Dquarkus.datasource.jdbc.url=jdbc:postgresql://localhost:5432/gms-db -Dquarkus.datasource.password=no_secret -Dquarkus.datasource.username=dsr-gms_user -jar target/quarkus-app/quarkus-run.jar
```

## Local start of application with docker-compose
Prerequisite for the local deployment are the following two host names for the localhost IP 127.0.0.1 <br> 
**_NOTE:_** on Windows entered in the hosts file (usually located under C:\Windows\System32\drivers\etc)
```
127.0.0.1 dsr.gms
127.0.0.1 dsr.gms-mtls
```

Build the GMS image locally
```shell script
mvn package -ntp -DskipTests -Dquarkus.container-image.build=true
```

## Health Check - localhost
http://localhost:9000/management/health         <br>
http://localhost:9000/management/health/live    <br>
http://localhost:9000/management/health/ready   <br>

## Metrics 
http://localhost:9000/management/metrics  
