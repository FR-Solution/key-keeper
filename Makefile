project = key-keeper#change for new project
release = v1.0.0

tag = $(DOCKER_USER)/$(project):$(release)
pwd = $(shell pwd)
module = $(shell head -n 1 1 go.mod| awk '{print $2}')

build-and-push:
	docker build -t $(tag) --build-arg VERSION=$(release) --build-arg PROJECT=$(project) -f Dockerfile .
	# docker image push $(tag)

formatting:
	go fmt ./...
	go install github.com/daixiang0/gci@latest	
	gci write --skip-generated -s standard -s default -s "prefix($(module))" .

linter:
	docker run --rm -v $(pwd):/app -w /app golangci/golangci-lint:v1.49.0 golangci-lint run -v