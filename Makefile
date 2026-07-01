.PHONY: install dev test test-cov lint format run run-dashboard run-prod kill totp clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install runtime dependencies
	pip install -r requirements.txt

dev: ## Install all dependencies (runtime + dev)
	pip install -r requirements-dev.txt

test: ## Run test suite
	python -m pytest tests/ -v --tb=short

test-cov: ## Run tests with coverage report
	python -m pytest tests/ -v --cov=honeypot --cov=dashboard --cov-report=term-missing --cov-report=html:htmlcov

lint: ## Run linters (flake8 + mypy)
	flake8 honeypot/ dashboard/ --max-line-length=120 --ignore=E501,W503,E402
	mypy honeypot/ dashboard/ --ignore-missing-imports --no-strict-optional

format: ## Format code with black
	black honeypot/ dashboard/ tests/ config.py --line-length=120

run: ## Run the honeypot
	python -m honeypot.mavlink_honeypot

run-dashboard: ## Run dashboard (dev mode, single-thread)
	python dashboard/app.py

run-prod: ## Run dashboard with gunicorn (multi-threaded, production-ready)
	gunicorn --worker-class gthread --workers 2 --threads 4 --bind 0.0.0.0:5000 --timeout 120 --chdir $(shell pwd) 'dashboard.app:app'

kill: ## Kill all dashboard/honeypot processes
	@-pkill -f "python.*app.py" 2>/dev/null
	@-pkill -f "gunicorn" 2>/dev/null
	@-pkill -f "python.*honeypot" 2>/dev/null
	@sleep 1
	@echo "✅ All processes killed"

totp: ## Generate current TOTP code
	@python -c "import pyotp,os; s=os.environ.get('TOTP_SECRET',''); exec('if not s:\n try:\n  from dotenv import load_dotenv; load_dotenv()\n  s=os.environ.get(\"TOTP_SECRET\",\"\")\n except: pass'); exec('if not s:\n import sys;sys.path.insert(0,\".\");from config import settings;s=settings.totp_secret or \"\"'); exec('if not s and os.path.exists(\"config/totp_secret.key\"):\n s=open(\"config/totp_secret.key\").read().strip()'); print(f'🔑 TOTP Code: {pyotp.TOTP(s).now()}') if s else print('❌ No TOTP secret found')"

clean: ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	rm -rf htmlcov .coverage .mypy_cache .pytest_cache
	@echo "Cleaned."
