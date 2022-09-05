setup-pre-commit:
	pip install --user pre-commit
	pre-commit install
	pre-commit install --hook-type commit-msg

setup: setup-pre-commit
	pip install black
	pip install isort
