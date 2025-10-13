# Debloat container image

## On build system

### Build container image
   ```bash
   # vi Dockerfile to adjust version number, e.g. 0.3.2
   make build
   docker push harbor.svc.marmira.com/services/httpshow:0.3.2
   ```

### Start BAFFS
   ```bash
   docker run -d --name baffs --privileged=true -v /var/tmp/docker/:/var/lib/docker -v /var/tmp/baffs:/var/lib/data -p 8000:8000 justinzhf/baffs:latest
   docker exec -it baffs bash
   ```

## In BAFFS

### Prepare to profile image

   In one terminal, start application within BAFFS and profile it
   ```bash
   docker pull harbor.svc.marmira.com/services/httpshow:0.3.2
   baffs shadow --images=harbor.svc.marmira.com/services/httpshow:0.3.2
   docker run -it --rm --name the_app --env-file /var/lib/data/httpshow/test.env -p 8000:8000 harbor.svc.marmira.com/services/httpshow:0.3.2
   ```

### Use application

   E.g., for HTTPShow, open web browser and use it

### In another terminal, exec into container to flag files used for shell access
   ```bash
   docker exec -it the_app /bin/bash
   ```

### Stop application
   ```bash
   ^C
   ```

### Debloat image
   ```bash
   baffs debloat --images=harbor.svc.marmira.com/services/httpshow:0.3.2
   ```

### Check reduction
   ```bash
   docker image ls
   ```

### Push debloated image to Harbor
   ```bash
   docker push harbor.svc.marmira.com/services/httpshow:0.3.2-baffs
   ```

## On build system

### Pull debloated image from Harbor
   ```bash
   docker pull harbor.svc.marmira.com/services/httpshow:0.3.2-baffs
   ```

### Tag debloated image for quay.io
   ```bash
   img="$(docker image ls harbor.svc.marmira.com/services/httpshow:0.3.2-baffs | awk '/httpshow/{print $3}')"
   docker tag ${img} quay.io/miniboat/httpshow:0.3.2
   ```

### Update image on quay.io
   ```bash
   docker push quay.io/miniboat/httpshow:0.3.2
   ```
