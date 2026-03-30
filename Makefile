.PHONY: build
build:
	docker compose build

.PHONY: dev
dev: build
	docker compose up --watch

.PHONY: clean
clean:
	docker compose down --remove-orphans --volumes --rmi=all
	cargo clean

.PHONY: publish
publish:
	./scripts/deploy.sh

.PHONY: publish-amd64
publish-amd64:
	./scripts/deploy.sh --arch amd64

.PHONY: publish-arm64
publish-arm64:
	./scripts/deploy.sh --arch arm64

.PHONY: publish-no-latest
publish-no-latest:
	./scripts/deploy.sh --no-latest

.PHONY: publish-dry-run
publish-dry-run:
	./scripts/deploy.sh --dry-run

.PHONY: changelog
changelog:
	#SNAPCHAIN_VERSION=$(awk -F '"' '/^version =/ {print $2}' ./Cargo.toml)
	echo "Generating changelog for version: $(SNAPCHAIN_VERSION)"
	git cliff --unreleased --tag $(SNAPCHAIN_VERSION) --prepend CHANGELOG.md