# Include variables from the .envrc file
include .envrc

# ==================================================================================== #
# HELPERS
# ==================================================================================== #

## help: print this help message 
.PHONY: help
help:
		@echo 'Usage:'
		@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

.PHONY: confirm
confirm:
		@echo -n 'Are you sure? [y/N] ' && read ans && [ $${ans:-N} = y ]


# ==================================================================================== #
# DEVELOPMENT
# ==================================================================================== #

## run/api: run the cmd/api application
.PHONY: run/api
run/api:
		air 

## db/psql: connect to the database using psql
.PHONY: db/psql
db/psql:
		psql ${DATABASE_URL}

## db/migrations/new name=$1: create a new database migration
.PHONY: db/migrations/new
db/migrations/new:
		@echo "Creating migration files for ${name}..."
		migrate create -seq -ext=.sql -dir=./migrations ${name}

## db/migrations/force version=$1: force migration version
.PHONY: db/migrations/force
db/migrations/force:
		@echo "Force migration to version ${version}..."
		migrate -path=./migrations -database=$DATABASE_URL force ${version}

## db/migrations/up: apply all up database migrations
.PHONY: db/migrations/up 
db/migrations/up: confirm
		@echo "Running up migrations...."
		migrate -path ./migrations -database ${DATABASE_URL} up


# ==================================================================================== #
# QUALITY CONTROL
# ==================================================================================== #
.PHONY: audit
audit:
		@echo 'Tidying and verifying module dependencies...'
		go mod tidy
		go mod verify
		@echo 'Formatting code...'
		go fmt ./...
		@echo 'Vetting code...'
		go vet ./...
		staticcheck ./...
		@echo 'Running tests...'
		go test -race -vet=off ./...

# ==================================================================================== #
# BUILD
# ==================================================================================== #

## build/api: build the cmd/api application
.PHONY: build/api 
build/api:
	@echo 'Building cmd/api...' 
	go build -o=./bin/api ./cmd/api
