BUILD_DIR ?= bin
BUILD_PACKAGE ?= ./cmd/main.go
PROJECT_PKG = github.com/bogatyr285/auth-go

VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null || git symbolic-ref -q --short HEAD)
COMMIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null)
BUILD_DATE ?= $(shell date +%FT%T%z)
# remove debug info from the binary & make it smaller
LDFLAGS += -s -w
LDFLAGS += -X ${PROJECT_PKG}/internal/buildinfo.version=${VERSION} -X ${PROJECT_PKG}/internal/buildinfo.commitHash=${COMMIT_HASH} -X ${PROJECT_PKG}/internal/buildinfo.buildDate=${BUILD_DATE}

build:
	go build ${GOARGS} -tags "${GOTAGS}" -ldflags "${LDFLAGS}" -o ${BUILD_DIR}/${BINARY_NAME} ${BUILD_PACKAGE}

.PHONY: docker-build docker-up docker-down docker-restart clean generate-keys e2e-test

docker-build:
	docker build -t ${PROJECT_PKG}:${COMMIT_HASH} .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-restart: docker-down docker-up

docker-run: docker-build docker-up
	docker-compose logs -f

clean:
	docker-compose down --rmi all --volumes --remove-orphans && rm -rf ${BUILD_DIR}

generate-keys:
	openssl genpkey -algorithm ed25519 -out jwtEd25519.key
	openssl pkey -in jwtEd25519.key -pubout -out jwtEd25519.key.pub

e2e-test:
	go test ./e2e_test -v

unit-test:
	go test -v ./internal/pkg/jwt ./internal/auth/usecase