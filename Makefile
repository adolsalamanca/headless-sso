SHELL := bash
COOKIES_PATH := $HOME/.headless-sso

.PHONY: run
run:
	@$(rm *.png || true)
	@$(rm COOKIES_PATH || true)
	@aws sso login  --no-browser | go run main.go
