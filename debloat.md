# Debloat container image

## On build system

### Build container image
   ```bash
   make info
   # Check tag is ok, if not: vi Dockerfile to adjust target repository (REPO=)
   make build
   make push
   ```

### Start BAFFS
   ```bash
   docker run -d --name baffs --privileged=true \
      -v /var/tmp/docker/:/var/lib/docker \
      -v ./samples:/var/lib/data \
      -p 8000:8000 \
      justinzhf/baffs:latest
   docker exec -it baffs bash
   ```

## In BAFFS

### Set environment

   The container images' tag is used repeatedly. Instead of specifying it each time, set an environment variable,
   ```bash
   export tag=my-repo.example.com/airlock/httpshow:0.4.0
   ```

### Prepare to profile image

   In one terminal, start application within BAFFS and profile it
   ```bash
   docker pull "${tag}"
   baffs shadow --images="${tag}"
   docker run -it --rm --name the_app --env-file /var/lib/data/debloat.env -p 8000:8000 "${tag}"
   ```

### In another terminal

   Exec into container to flag files used for shell access
   ```bash
   docker exec -it the_app /bin/bash
   ```

   Read all application files to make sure they remain included in image:
   ```bash
   find app/ -type f -print -exec cp {} /dev/null \;
   ```

   Exit from application container and test HTML & JSON responses:
   ```
   curl -s http://localhost:8000/api
   curl -s http://localhost:8000/api -H "Accept: application/json"
   ```

## Back on build system

### Use application

   Open web browser and use it

## In BAFFS again

### Stop application
   ```bash
   ^C
   ```

### Debloat image
   ```bash
   baffs debloat --images="${tag}"
   ```

### Check reduction
   ```bash
   docker image ls
   ```

### Push debloated image to container repo
   ```bash
   docker login "${tag%%/*}"
   docker push "${tag}"-baffs
   ```

## On build system

### Tag debloated image for quay.io
   ```bash
   make quay
   ```

### Update image on quay.io
   ```bash
   make quay-push
   ```
