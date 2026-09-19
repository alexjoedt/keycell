BINDIR ?= $(HOME)/.local/bin
UNITDIR ?= $(HOME)/.config/systemd/user

## help: print this help message
.PHONY: help
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

## tidy: format code and tidy modfile
.PHONY: tidy
tidy:
	go fmt ./...
	go mod tidy -v

## test: run the tests with the race detector
.PHONY: test
test:
	go test -race ./...

## lint: run go vet and golangci-lint
.PHONY: lint
lint:
	go vet ./...
	golangci-lint run

## audit: run quality control checks
.PHONY: audit
audit: lint
	go test -race -vet=off ./...
	go mod verify

## build: build keycell, keycelld and docker-credential-keycell into bin/
.PHONY: build
build:
	go mod verify
	go build -ldflags='-s' -o=./bin/ ./cmd/...

## install: build and install the three binaries into ~/.local/bin (BINDIR)
.PHONY: install
install: build
	install -Dm755 bin/keycell bin/keycelld bin/docker-credential-keycell -t $(BINDIR)

## install-service: install the systemd user unit into ~/.config/systemd/user (UNITDIR) and reload
.PHONY: install-service
install-service:
	install -Dm644 contrib/keycell.service -t $(UNITDIR)
	systemctl --user daemon-reload

## uninstall: remove the binaries and the systemd user unit
.PHONY: uninstall
uninstall:
	rm -f $(BINDIR)/keycell $(BINDIR)/keycelld $(BINDIR)/docker-credential-keycell
	rm -f $(UNITDIR)/keycell.service
