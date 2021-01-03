.PHONY: db migrate run test testv test-db coverage protos

db:
	docker run -d --rm -ti --network host -e POSTGRES_PASSWORD=secret postgres

migrate:
	migrate -source file://migrations \
		-database postgres://postgres:secret@localhost/postgres?sslmode=disable up

run:
	go run ./cmd/main.go

build:
	go build ./cmd/main.go

clean:
	rm main -f
	go clean -testcache

test:
	go test ./...

testv:
	go test ./... -v

coverage:
	go test ./... -cover

protos:
	protoc -I ~/projects/syncapod/syncapod-protos/ \
		--go_out=internal/protos/ \
		--go-grpc_out=internal/protos/ \
		~/projects/syncapod/syncapod-protos/*
