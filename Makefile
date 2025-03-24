BIN_NAME := template

SRC := $(realpath main.py)

DEST := /usr/local/bin/$(BIN_NAME)

.PHONY: install uninstall

install:
	@echo "Installing $(BIN_NAME)..."
	@if [ ! -f "$(SRC)" ]; then \
		echo "Error: main.py not found."; \
		exit 1; \
	fi
	@if [ -L "$(DEST)" ]; then \
		echo "Removing existing symlink at $(DEST)"; \
		sudo rm "$(DEST)"; \
	fi
	sudo ln -s "$(SRC)" "$(DEST)"
	@echo "Done. You can now run '$(BIN_NAME)' from anywhere."
