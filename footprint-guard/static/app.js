// Digital Footprint Scanner - Frontend JavaScript

document.getElementById('scanForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const domain = document.getElementById('domain').value.trim();
    
    // Validate at least one field is filled
    if (!username && !email && !domain) {
        showError('Please enter at least a username, email, or domain');
        return;
    }
    
    // Show loading, hide results and errors
    document.getElementById('loading').style.display = 'block';
    document.getElementById('results').style.display = 'none';
    document.getElementById('error-message').style.display = 'none';
    
    // Disable submit button
    const submitBtn = this.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.querySelector('.btn-text').style.display = 'none';
    submitBtn.querySelector('.btn-loading').style.display = 'inline';
    
    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email, domain })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Scan failed');
        }
        
        displayResults(data);
        
    } catch (error) {
        showError(error.message);
    } finally {
        // Hide loading, enable button
        document.getElementById('loading').style.display = 'none';
        submitBtn.disabled = false;
        submitBtn.querySelector('.btn-text').style.display = 'inline';
        submitBtn.querySelector('.btn-loading').style.display = 'none';
    }
});

function displayResults(data) {
    const resultsSection = document.getElementById('results');
    
    // Update summary cards
    const summary = data.report.summary || {};
    document.getElementById('total-exposures').textContent = summary.total_exposures || 0;
    document.getElementById('high-risk').textContent = summary.high_risk_platforms || 0;
    document.getElementById('medium-risk').textContent = summary.medium_risk_platforms || 0;
    
    const lowRisk = (summary.total_exposures || 0) - (summary.high_risk_platforms || 0) - (summary.medium_risk_platforms || 0);
    document.getElementById('low-risk').textContent = Math.max(0, lowRisk);
    
    // Display social media results
    const socialMediaContainer = document.getElementById('social-media-results');
    if (data.username_scan && data.username_scan.length > 0) {
        socialMediaContainer.innerHTML = data.username_scan.map(result => `
            <div class="result-item ${result.risk_level === 'High' ? 'high-risk' : result.risk_level === 'Medium' ? 'medium-risk' : 'low-risk'}">
                <h5>${result.platform} <span style="float: right; font-size: 0.8rem;">${result.risk_level} Risk</span></h5>
                <p><a href="${result.url}" target="_blank" rel="noopener">${result.url}</a></p>
                <p style="margin-top: 0.5rem;"><strong>Action:</strong> Review privacy settings and consider deleting if unused</p>
            </div>
        `).join('');
    } else {
        socialMediaContainer.innerHTML = '<p>No social media accounts found with this username.</p>';
    }
    
    // Display email and domain results
    const emailDomainContainer = document.getElementById('email-domain-results');
    let emailDomainHTML = '';
    
    if (data.email_scan && Object.keys(data.email_scan).length > 0) {
        if (data.email_scan.breaches && data.email_scan.breaches.length > 0) {
            emailDomainHTML += '<div class="result-item high-risk"><h5>⚠️ Data Breaches Detected</h5>';
            data.email_scan.breaches.forEach(breach => {
                emailDomainHTML += `<p><strong>${breach.source}</strong>: ${breach.description}</p>`;
            });
            emailDomainHTML += '</div>';
        }
        
        if (data.email_scan.domain_info && Object.keys(data.email_scan.domain_info).length > 0) {
            const domainInfo = data.email_scan.domain_info;
            emailDomainHTML += '<div class="result-item medium-risk"><h5>🌐 Domain Information</h5>';
            if (domainInfo.whois && domainInfo.whois.registrar) {
                emailDomainHTML += `<p><strong>Registrar:</strong> ${domainInfo.whois.registrar}</p>`;
            }
            if (domainInfo.whois && domainInfo.whois.creation_date) {
                emailDomainHTML += `<p><strong>Created:</strong> ${domainInfo.whois.creation_date}</p>`;
            }
            if (domainInfo.subdomains && domainInfo.subdomains.length > 0) {
                emailDomainHTML += `<p><strong>Subdomains found:</strong> ${domainInfo.subdomains.join(', ')}</p>`;
            }
            emailDomainHTML += '</div>';
        }
    }
    
    if (data.domain_scan && Object.keys(data.domain_scan).length > 0) {
        const domainInfo = data.domain_scan;
        emailDomainHTML += '<div class="result-item medium-risk"><h5>🌐 Domain Analysis</h5>';
        if (domainInfo.whois && domainInfo.whois.registrar) {
            emailDomainHTML += `<p><strong>Registrar:</strong> ${domainInfo.whois.registrar}</p>`;
        }
        if (domainInfo.dns_records && Object.keys(domainInfo.dns_records).length > 0) {
            emailDomainHTML += '<p><strong>DNS Records:</strong></p><ul style="margin-left: 1.5rem;">';
            for (const [type, records] of Object.entries(domainInfo.dns_records)) {
                records.forEach(record => {
                    emailDomainHTML += `<li>${type}: ${record}</li>`;
                });
            }
            emailDomainHTML += '</ul>';
        }
        if (domainInfo.subdomains && domainInfo.subdomains.length > 0) {
            emailDomainHTML += `<p><strong>Subdomains:</strong> ${domainInfo.subdomains.join(', ')}</p>`;
        }
        emailDomainHTML += '</div>';
    }
    
    if (!emailDomainHTML) {
        emailDomainHTML = '<p>No email or domain data to display.</p>';
    }
    emailDomainContainer.innerHTML = emailDomainHTML;
    
    // Display recommendations
    const recommendationsContainer = document.getElementById('recommendations');
    if (data.report.recommendations && data.report.recommendations.length > 0) {
        recommendationsContainer.innerHTML = data.report.recommendations.map(rec => `
            <div class="recommendation-item ${rec.priority.toLowerCase()}">
                <h5>
                    <span class="priority-badge ${rec.priority.toLowerCase()}">${rec.priority}</span>
                    ${rec.category}
                </h5>
                <p><strong>Action:</strong> ${rec.action}</p>
                <p>${rec.details}</p>
                ${rec.platforms ? `<p style="margin-top: 0.5rem;"><strong>Affects:</strong> ${rec.platforms.join(', ')}</p>` : ''}
            </div>
        `).join('');
    } else {
        recommendationsContainer.innerHTML = '<p>No specific recommendations at this time.</p>';
    }
    
    // Show results section
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

function showError(message) {
    const errorDiv = document.getElementById('error-message');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    errorDiv.scrollIntoView({ behavior: 'smooth' });
}

// Add input validation feedback
document.querySelectorAll('input').forEach(input => {
    input.addEventListener('blur', function() {
        if (this.value && this.type === 'email') {
            const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailPattern.test(this.value)) {
                this.style.borderColor = 'var(--danger-color)';
            } else {
                this.style.borderColor = 'var(--success-color)';
            }
        } else if (this.value && this.id === 'username') {
            if (this.value.length < 3) {
                this.style.borderColor = 'var(--danger-color)';
            } else {
                this.style.borderColor = 'var(--success-color)';
            }
        }
    });
    
    input.addEventListener('focus', function() {
        this.style.borderColor = 'var(--border-color)';
    });
});
