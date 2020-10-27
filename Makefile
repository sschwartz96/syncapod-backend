.PHONY: db migrate run test

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
	rm main

test:
	docker run -d --rm -ti --name pg_test --network host -e POSTGRES_PASSWORD=secret postgres
	sleep 1.25 # wait enough time to run migrations
	migrate  -source file://migrations \
		-database postgres://postgres:secret@localhost/postgres?sslmode=disable up
	go test ./... -race; docker stop pg_test -t 1
