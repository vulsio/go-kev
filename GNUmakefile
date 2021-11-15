.PHONY: \
	all \
	build \
	install \
	vendor \
	lint \
	vet \
	fmt \
	fmtcheck \
	pretest \
	test \
	integration \
	cov \
	clean \
	build-integration \
	clean-integration \
	fetch-rdb \
	fetch-redis \
	diff-cveid \
	diff-package \
	diff-server-rdb \
	diff-server-redis \
	diff-server-rdb-redis

SRCS = $(shell git ls-files '*.go')
PKGS = $(shell go list ./...)
VERSION := $(shell git describe --tags --abbrev=0)
REVISION := $(shell git rev-parse --short HEAD)
BUILDTIME := $(shell date "+%Y%m%d_%H%M%S")
LDFLAGS := -X 'github.com/MaineK00n/go-kev/config.Version=$(VERSION)' \
	-X 'github.com/MaineK00n/go-kev/config.Revision=$(REVISION)'
GO := GO111MODULE=on go
GO_OFF := GO111MODULE=off go

all: build test

build: main.go 
	$(GO) build -ldflags "$(LDFLAGS)" -o go-kev $<

install: main.go
	$(GO) install -ldflags "$(LDFLAGS)"

lint:
	$(GO_OFF) get -u github.com/mgechev/revive
	revive -config ./.revive.toml -formatter plain $(PKGS)

vet:
	echo $(PKGS) | xargs env $(GO) vet || exit;

fmt:
	gofmt -w $(SRCS)

fmtcheck:
	$(foreach file,$(SRCS),gofmt -d $(file);)

pretest: lint vet fmtcheck

test: pretest
	$(GO) test -cover -v ./... || exit;

cov:
	@ go get -v github.com/axw/gocov/gocov
	@ go get golang.org/x/tools/cmd/cover
	gocov test | gocov report

clean:
	$(foreach pkg,$(PKGS),go clean $(pkg) || exit;)

BRANCH := $(shell git symbolic-ref --short HEAD)
build-integration:
	@ git stash save
	$(GO) build -ldflags "$(LDFLAGS)" -o integration/go-kev.new
	git checkout $(shell git describe --tags --abbrev=0)
	@git reset --hard
	$(GO) build -ldflags "$(LDFLAGS)" -o integration/go-kev.old
	git checkout $(BRANCH)
	-@ git stash apply stash@{0} && git stash drop stash@{0}

clean-integration:
	-pkill go-kev.old
	-pkill go-kev.new
	-rm integration/go-kev.old integration/go-kev.new integration/go-kev.old.sqlite3 integration/go-kev.new.sqlite3
	-rm -rf integration/diff
	-docker kill redis-old redis-new
	-docker rm redis-old redis-new

fetch-rdb:
	integration/go-kev.old fetch kevuln --dbpath=integration/go-kev.old.sqlite3
	integration/go-kev.new fetch kevuln --dbpath=integration/go-kev.new.sqlite3

fetch-redis:
	docker run --name redis-old -d -p 127.0.0.1:6379:6379 redis
	docker run --name redis-new -d -p 127.0.0.1:6380:6379 redis

	integration/go-kev.old fetch kevuln --dbtype redis --dbpath "redis://127.0.0.1:6379/0"
	integration/go-kev.new fetch kevuln --dbtype redis --dbpath "redis://127.0.0.1:6380/0"

diff-cves:
	@ python integration/diff_server_mode.py cves --sample_rate 0.01
	@ python integration/diff_server_mode.py multi-cves --sample_rate 0.01

diff-server-rdb:
	integration/go-kev.old server --dbpath=integration/go-kev.old.sqlite3 --port 1325 > /dev/null 2>&1 & 
	integration/go-kev.new server --dbpath=integration/go-kev.new.sqlite3 --port 1326 > /dev/null 2>&1 &
	make diff-cves
	pkill go-kev.old 
	pkill go-kev.new

diff-server-redis:
	integration/go-kev.old server --dbtype redis --dbpath "redis://127.0.0.1:6379/0" --port 1325 > /dev/null 2>&1 & 
	integration/go-kev.new server --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --port 1326 > /dev/null 2>&1 &
	make diff-cves
	pkill go-kev.old 
	pkill go-kev.new

diff-server-rdb-redis:
	integration/go-kev.new server --dbpath=integration/go-kev.new.sqlite3 --port 1325 > /dev/null 2>&1 &
	integration/go-kev.new server --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --port 1326 > /dev/null 2>&1 &
	make diff-cves
	pkill go-kev.new