.PHONY: build run clean setup

BINARY_NAME=bin/recon-engine
VENV_ACTIVATE=. .venv/bin/activate
PYTHON=.venv/bin/python

setup:
	@echo "Setting up virtual environment..."
	python3 -m venv .venv
	$(VENV_ACTIVATE) && pip install -r requirements.txt
	@echo "Setup complete."

build:
	@echo "Building Go Recon Engine..."
	@mkdir -p bin
	@go build -o $(BINARY_NAME) ./cmd/recon-engine
	@echo "Build complete: $(BINARY_NAME)"

run: build
	@echo "Starting Streamlit App..."
	@export RECON_BIN_PATH=$(BINARY_NAME) && $(PYTHON) -m streamlit run app/app.py

clean:
	@echo "Cleaning up..."
	@rm -f $(BINARY_NAME)
	@rm -rf .venv
