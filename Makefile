.PHONY: test

test:
	@echo "Running tests..."
	@go test -v -vet=all -cover ./...
	@echo "Done."