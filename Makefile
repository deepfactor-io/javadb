LDFLAGS=-ldflags "-s -w"
GO_SRCS := $(shell find . -name *.go)

.PHONY: test
test:
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: build
build: df-java-db

df-java-db: $(GO_SRCS)
	go build $(LDFLAGS) ./cmd/df-java-db

.PHONY: db-crawl
db-crawl: df-java-db
	./df-java-db --cache-dir ./cache crawl

.PHONY: db-build
db-build: df-java-db
	./df-java-db --cache-dir ./cache build

.PHONY: db-compress
db-compress: cache/*
	tar cvzf cache/db/javadb.tar.gz -C cache/db/ df-java.db metadata.json

.PHONY: dep-db-build
dep-db-build: df-java-db
	./df-java-db --cache-dir ./cache dependency-build

.PHONY: dep-db-compress
dep-db-compress: cache/*
	tar cvzf cache/dep-db/javadependencydb.tar.gz -C cache/dep-db/ df-java-dependency.db metadata.json

.PHONY: clean
clean:
	rm -rf cache/
