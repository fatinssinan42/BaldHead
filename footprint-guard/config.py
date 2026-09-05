import os

# Secret key for Flask sessions
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# API Keys (Add your own keys for extended functionality)
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
HAVE_I_BEEN_PWNED_API_KEY = os.environ.get('HAVE_I_BEEN_PWNED_API_KEY', '')

# Rate limiting
RATE_LIMIT_PER_MINUTE = 10

# User agent for requests
USER_AGENT = 'FootprintGuard/1.0 (Educational Security Tool)'