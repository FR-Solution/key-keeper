release = $(shell cat .release)
tag = $(DOCKER_USER)/key-keeper:$(release)

build-and-push:
	docker build -t $(tag) --build-arg VERSION=$(release) -f Dockerfile .
	docker image push $(tag)

formatting:
	go install github.com/daixiang0/gci@latest	
	gci write --skip-generated -s standard -s default -s "prefix(github.com/fraima/key-keeper)" .