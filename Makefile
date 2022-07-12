release = $(shell cat .release)
tag = $(DOCKER_USER)/key-keeper:$(release)

build-and-push:
	docker build -t $(tag) --build-arg VERSION=$(release) -f Dockerfile .
	docker image push $(tag)