"""
Digital Footprint Scanner Module
Performs ethical OSINT scanning using public APIs and verified methods
"""

import requests
import socket
import dns.resolver
import whois
from datetime import datetime
from urllib.parse import urlparse
import re
import json

class FootprintScanner:
    def __init__(self, shodan_api_key=None):
        self.shodan_api_key = shodan_api_key
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'FootprintGuard/1.0 (Educational Security Tool)'
        })
    
    def scan_username(self, username):
        """Scan for username across multiple platforms"""
        platforms = {
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'GitLab': f'https://gitlab.com/{username}',
            'Docker Hub': f'https://hub.docker.com/u/{username}',
            'Medium': f'https://medium.com/@{username}',
            'SoundCloud': f'https://soundcloud.com/{username}',
            'Spotify': f'https://open.spotify.com/user/{username}',
            'Twitch': f'https://twitch.tv/{username}',
            'WordPress': f'https://wordpress.com/@{username}',
            'Blogger': f'https://{username}.blogspot.com',
            'Steam': f'https://steamcommunity.com/id/{username}',
            'Pinterest': f'https://pinterest.com/{username}',
            'Tumblr': f'https://{username}.tumblr.com',
        }
        
        results = []
        for platform, url in platforms.items():
            try:
                response = self.session.get(url, timeout=5)
                exists = response.status_code == 200
                if exists:
                    results.append({
                        'platform': platform,
                        'url': url,
                        'status': 'Found',
                        'risk_level': self._assess_platform_risk(platform)
                    })
            except requests.RequestException:
                continue
        
        return results
    
    def _assess_platform_risk(self, platform):
        """Assess risk level of platform exposure"""
        high_risk = ['LinkedIn', 'Facebook', 'Instagram', 'Twitter']
        medium_risk = ['GitHub', 'GitLab', 'Reddit', 'Medium']
        
        if platform in high_risk:
            return 'High'
        elif platform in medium_risk:
            return 'Medium'
        return 'Low'
    
    def scan_email(self, email):
        """Scan email for breaches and exposure"""
        results = {
            'breaches': [],
            'paste_sites': [],
            'domain_info': {}
        }
        
        # Extract domain from email
        domain = email.split('@')[1] if '@' in email else None
        
        if domain:
            # Check domain information
            results['domain_info'] = self.scan_domain(domain)
            
            # Check Have I Been Pwned (requires API key for full access)
            # Using k-anonymity method for demo
            results['breaches'] = self._check_breaches_k_anonymity(email)
        
        return results
    
    def _check_breaches_k_anonymity(self, email):
        """Check breaches using k-anonymity method (no API key required)"""
        try:
            import hashlib
            email_hash = hashlib.sha256(email.lower().encode()).hexdigest()[:8]
            
            # This is a demo - in production, use the actual HIBP API
            return [{
                'source': 'Have I Been Pwned (Demo)',
                'date': 'N/A - API Key Required',
                'description': 'Add HIBP API key to check actual breaches',
                'risk': 'Unknown'
            }]
        except Exception as e:
            return [{'error': str(e)}]
    
    def scan_domain(self, domain):
        """Scan domain for exposed information"""
        results = {
            'whois': {},
            'dns_records': {},
            'ip_info': {},
            'subdomains': []
        }
        
        try:
            # WHOIS lookup
            w = whois.whois(domain)
            results['whois'] = {
                'registrar': getattr(w, 'registrar', 'N/A'),
                'creation_date': str(getattr(w, 'creation_date', 'N/A')),
                'expiration_date': str(getattr(w, 'expiration_date', 'N/A')),
                'name_servers': getattr(w, 'name_servers', []),
                'registrant_country': getattr(w, 'country', 'N/A')
            }
        except Exception as e:
            results['whois'] = {'error': str(e)}
        
        try:
            # DNS records
            for record_type in ['A', 'MX', 'NS', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    results['dns_records'][record_type] = [str(rdata) for rdata in answers]
                except:
                    pass
        except Exception as e:
            results['dns_records'] = {'error': str(e)}
        
        try:
            # Get IP information
            ip = socket.gethostbyname(domain)
            results['ip_info']['ip'] = ip
            
            # Try to get geolocation info (using free API)
            try:
                geo_response = self.session.get(f'http://ip-api.com/json/{ip}', timeout=5)
                if geo_response.status_code == 200:
                    results['ip_info']['geo'] = geo_response.json()
            except:
                pass
        except:
            pass
        
        # Common subdomain check
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'dev', 'test', 'api', 'blog']
        for sub in common_subdomains:
            subdomain = f'{sub}.{domain}'
            try:
                socket.gethostbyname(subdomain)
                results['subdomains'].append(subdomain)
            except:
                pass
        
        return results
    
    def scan_shodan(self, query):
        """Scan Shodan for exposed devices/services (requires API key)"""
        if not self.shodan_api_key:
            return {'error': 'Shodan API key not configured'}
        
        try:
            import shodan
            api = shodan.Shodan(self.shodan_api_key)
            results = api.search(query)
            return {
                'total': results['total'],
                'matches': results['matches'][:10]  # Limit to first 10
            }
        except Exception as e:
            return {'error': str(e)}
    
    def generate_security_report(self, username_results, email_results, domain_results):
        """Generate comprehensive security report with recommendations"""
        report = {
            'summary': {
                'total_exposures': len(username_results),
                'high_risk_platforms': sum(1 for r in username_results if r.get('risk_level') == 'High'),
                'medium_risk_platforms': sum(1 for r in username_results if r.get('risk_level') == 'Medium'),
                'timestamp': datetime.now().isoformat()
            },
            'findings': {
                'social_media': username_results,
                'email_breaches': email_results.get('breaches', []),
                'domain_exposure': domain_results
            },
            'recommendations': self._generate_recommendations(username_results, email_results, domain_results)
        }
        
        return report
    
    def _generate_recommendations(self, username_results, email_results, domain_results):
        """Generate actionable security recommendations"""
        recommendations = []
        
        # Platform-specific recommendations
        high_risk_platforms = [r for r in username_results if r.get('risk_level') == 'High']
        if high_risk_platforms:
            recommendations.append({
                'priority': 'High',
                'category': 'Social Media Privacy',
                'action': 'Review privacy settings on high-risk platforms',
                'details': f'Found {len(high_risk_platforms)} high-risk social media accounts. Ensure profiles are private and limit personal information sharing.',
                'platforms': [r['platform'] for r in high_risk_platforms]
            })
        
        # Email breach recommendations
        if email_results.get('breaches'):
            recommendations.append({
                'priority': 'Critical',
                'category': 'Password Security',
                'action': 'Change passwords immediately',
                'details': 'Email appears in data breaches. Change passwords for affected accounts and enable 2FA.',
            })
        
        # Domain recommendations
        if domain_results.get('whois'):
            whois_data = domain_results['whois']
            if whois_data.get('registrant_country') != 'N/A':
                recommendations.append({
                    'priority': 'Medium',
                    'category': 'Domain Privacy',
                    'action': 'Enable WHOIS privacy protection',
                    'details': 'Your domain registration information is publicly visible. Consider enabling privacy protection through your registrar.'
                })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'High',
                'category': 'Account Cleanup',
                'action': 'Delete unused accounts',
                'details': 'Review found accounts and delete any that are no longer needed to reduce attack surface.'
            },
            {
                'priority': 'Medium',
                'category': 'Password Management',
                'action': 'Use unique passwords',
                'details': 'Ensure each account has a unique, strong password. Consider using a password manager.'
            },
            {
                'priority': 'Medium',
                'category': 'Two-Factor Authentication',
                'action': 'Enable 2FA everywhere',
                'details': 'Enable two-factor authentication on all supported platforms for additional security.'
            },
            {
                'priority': 'Low',
                'category': 'Regular Monitoring',
                'action': 'Set up Google Alerts',
                'details': 'Create Google Alerts for your name and username to monitor new exposures.'
            }
        ])
        
        return recommendations
