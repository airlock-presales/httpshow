QUAY = quay.io/miniboat/httpshow
REPO = harbor.svc.marmira.com/services/httpshow
VERSION = $$(build-tools/get-version.sh)

all:
	@echo "info             Show container tag"
	@echo "build            Build container image (version: $(VERSION))"
	@echo "build-verbose    Build container image (version: $(VERSION))"
	@echo "push             Push image to repository (repo: $(REPO))"
	@echo "quay             Tag image for quay.io ($(QUAY):$(VERSION))"
	@echo "quay-push        Push image to quay.io"

info:
	@echo "Tag: $(REPO):$(VERSION)"

build:
	docker build . -t $(REPO):$(VERSION)

build-verbose:
	docker build . --progress=plain -t $(REPO):$(VERSION)

push:
	docker push $(REPO):$(VERSION)

quay:
	docker pull $(REPO):$(VERSION)-baffs
	(img="$$(docker image ls "$(REPO):$(VERSION)"-baffs | awk '/httpshow/{print $$3}')";docker tag "$${img}" $(QUAY):$(VERSION))

quay-push:
	docker push "$(QUAY):$(VERSION)"
