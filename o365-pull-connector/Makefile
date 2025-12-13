PYTHON=python3

run:
	$(PYTHON) -m o365_connector

test:
	$(PYTHON) -m pytest -q

lint:
	ruff check src tests

docker-up:
	docker-compose up --build
