from flask import Flask, render_template, request, jsonify, session
from modules.scanner import FootprintScanner
import config
import re

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Initialize scanner
scanner = FootprintScanner(shodan_api_key=config.SHODAN_API_KEY)

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username):
    """Validate username format"""
    if not username or len(username) < 3:
        return False
    pattern = r'^[a-zA-Z0-9_-]+$'
    return re.match(pattern, username) is not None

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Perform digital footprint scan"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    domain = data.get('domain', '').strip()
    
    # Validate inputs
    if not username and not email and not domain:
        return jsonify({'error': 'Please provide at least a username, email, or domain'}), 400
    
    results = {
        'username_scan': [],
        'email_scan': {},
        'domain_scan': {},
        'report': {}
    }
    
    try:
        # Scan username
        if username:
            if not validate_username(username):
                return jsonify({'error': 'Invalid username format. Use 3+ alphanumeric characters, underscores, or hyphens.'}), 400
            results['username_scan'] = scanner.scan_username(username)
        
        # Scan email
        if email:
            if not validate_email(email):
                return jsonify({'error': 'Invalid email format'}), 400
            results['email_scan'] = scanner.scan_email(email)
        
        # Scan domain
        if domain:
            # Extract domain from URL if full URL provided
            if domain.startswith('http'):
                from urllib.parse import urlparse
                domain = urlparse(domain).netloc
            results['domain_scan'] = scanner.scan_domain(domain)
        
        # Generate comprehensive report
        results['report'] = scanner.generate_security_report(
            results['username_scan'],
            results['email_scan'],
            results['domain_scan']
        )
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@app.route('/cleanup-guide')
def cleanup_guide():
    """Display cleanup guide"""
    return render_template('cleanup_guide.html')

@app.route('/privacy-tips')
def privacy_tips():
    """Display privacy tips"""
    return render_template('privacy_tips.html')

@app.errorhandler(404)
def not_found(e):
    return render_template('index.html'), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)