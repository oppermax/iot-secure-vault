VAULT_SIZE = 16
KEY_LENGTH = 16
VAULT_BYTES = $(shell echo $$(($(VAULT_SIZE) * $(KEY_LENGTH))))

CLIENT_VAULT = client/client_vault
SERVER_VAULT = server/server_vault
PYTHON = python3

.PHONY: init-vaults clean-vaults sync-vaults check-vault-health run-server run-client

init-vaults:
	@$(PYTHON) -c "import secrets; print('\n'.join(str(secrets.randbits($(KEY_LENGTH)*8)) for _ in range($(VAULT_SIZE))))" > $(SERVER_VAULT)
	@cp $(SERVER_VAULT) $(CLIENT_VAULT)
	@echo "Created vaults ($(VAULT_SIZE) keys)"

sync-vaults:
	@cp $(SERVER_VAULT) $(CLIENT_VAULT)

check-vault-health:
	@if cmp -s $(CLIENT_VAULT) $(SERVER_VAULT); then \
		echo "Vaults are in sync"; \
	else \
		echo "Vaults are out of sync"; \
	fi

clean-vaults:
	@rm -f $(CLIENT_VAULT) $(SERVER_VAULT)

run-server:
	$(PYTHON) -m server.main

run-client:
	$(PYTHON) -m client.main
