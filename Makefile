REPO = quay.io/miniboat/httpshow
VERSION = 0.3.0

all:
	@echo "build    Build container image (version: $(VERSION))"
	@echo "push     Push image to repository (repo: $(REPO))"

build:
	docker build . --progress=plain -t $(REPO):$(VERSION)

push:
	docker push $(REPO):$(VERSION)

