
from flask import Flask, request, jsonify, send_file, send_from_directory
import requests
from bs4 import BeautifulSoup
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph
import os
import time
import urllib.parse
import ssl
import socket
from datetime import datetime
import re

app = Flask(__name__, static_folder='public', static_url_path='')

def check_response_time(url):
    start_time = time.time()
    response = requests.get(url)
    end_time = time.time()
    return round((end_time - start_time) * 1000)  # Return in milliseconds

def check_ssl(url):
    hostname = urllib.parse.urlparse(url).hostname
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return {
                    'valid': True,
                    'version': ssock.version(),
                    'expiry': datetime.fromtimestamp(ssl.cert_time_to_seconds(ssock.getpeercert()['notAfter']))
                }
    except:
        return {'valid': False}

def analyze_website(url):
    results = {
        'securityIssues': [],
        'seoIssues': [],
        'performance': {},
        'headers': {},
        'url_analysis': {},
        'ratings': {
            'security': 0,
            'seo': 0,
            'performance': 0,
            'overall': 0
        },
        'details': {
            'images': 0,
            'links': 0,
            'colorScheme': [],
            'apiEndpoints': [],
            'technologies': []
        }
    }

    try:
        # Performance & Basic Checks
        response_time = check_response_time(url)
        results['performance']['responseTime'] = response_time
        results['performance']['statusCode'] = requests.get(url).status_code

        # SSL Check
        ssl_info = check_ssl(url)
        if not ssl_info['valid']:
            results['securityIssues'].append('Invalid or missing SSL certificate')

        # Fetch and analyze content
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(response.text, 'html.parser')

        # Enhanced Security Headers Check
        security_headers = {
            'Strict-Transport-Security': {'message': 'Missing HSTS header', 'recommended': 'max-age=31536000; includeSubDomains'},
            'X-Content-Type-Options': {'message': 'Missing X-Content-Type-Options header', 'recommended': 'nosniff'},
            'X-Frame-Options': {'message': 'Missing X-Frame-Options header', 'recommended': 'SAMEORIGIN'},
            'Content-Security-Policy': {'message': 'Missing Content-Security-Policy header', 'recommended': "default-src 'self'"},
            'X-XSS-Protection': {'message': 'Missing X-XSS-Protection header', 'recommended': '1; mode=block'},
            'Referrer-Policy': {'message': 'Missing Referrer-Policy header', 'recommended': 'strict-origin-when-cross-origin'}
        }

        headers = response.headers
        results['headers'] = dict(headers)
        
        for header, config in security_headers.items():
            if header not in headers:
                results['securityIssues'].append(config['message'])
            elif header in headers and headers[header] != config['recommended']:
                results['securityIssues'].append(f'{header} value not optimal (current: {headers[header]}, recommended: {config["recommended"]})')

        # URL Structure Analysis
        parsed_url = urllib.parse.urlparse(url)
        results['url_analysis'] = {
            'scheme': parsed_url.scheme,
            'netloc': parsed_url.netloc,
            'path': parsed_url.path,
            'params': parsed_url.params,
            'query': parsed_url.query
        }

        if parsed_url.scheme != 'https':
            results['securityIssues'].append('Not using HTTPS')

        # Enhanced SEO Analysis
        # Title Analysis
        title = soup.find('title')
        if not title:
            results['seoIssues'].append('Missing title tag')
        elif len(title.text.strip()) < 10:
            results['seoIssues'].append('Title tag too short (< 10 characters)')
        elif len(title.text.strip()) > 60:
            results['seoIssues'].append('Title tag too long (> 60 characters)')

        # Meta Description Analysis
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if not meta_desc:
            results['seoIssues'].append('Missing meta description')
        elif meta_desc.get('content', '') and len(meta_desc['content']) > 160:
            results['seoIssues'].append('Meta description too long (> 160 characters)')

        # Canonical Tag Check
        canonical = soup.find('link', attrs={'rel': 'canonical'})
        if not canonical:
            results['seoIssues'].append('Missing canonical tag')

        # Header Tags Hierarchy Analysis
        headers = {f'h{i}': len(soup.find_all(f'h{i}')) for i in range(1, 7)}
        if headers['h1'] == 0:
            results['seoIssues'].append('Missing H1 tag')
        elif headers['h1'] > 1:
            results['seoIssues'].append('Multiple H1 tags found')
        
        # Check header hierarchy
        for i in range(1, 5):
            if headers[f'h{i}'] == 0 and headers[f'h{i+1}'] > 0:
                results['seoIssues'].append(f'H{i+1} tag found without H{i} tag')

        # Robots.txt Check
        try:
            robots_response = requests.get(f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt")
            if robots_response.status_code != 200:
                results['seoIssues'].append('Missing robots.txt file')
        except:
            results['seoIssues'].append('Could not check robots.txt')

        # Sitemap Check
        try:
            sitemap_response = requests.get(f"{parsed_url.scheme}://{parsed_url.netloc}/sitemap.xml")
            if sitemap_response.status_code != 200:
                results['seoIssues'].append('Missing sitemap.xml')
        except:
            results['seoIssues'].append('Could not check sitemap.xml')

        # Image Alt Text Check
        images = soup.find_all('img')
        images_without_alt = [img for img in images if not img.get('alt')]
        if images_without_alt:
            results['seoIssues'].append(f'Found {len(images_without_alt)} images without alt text')

        # Mobile Responsiveness Check
        viewport = soup.find('meta', attrs={'name': 'viewport'})
        if not viewport:
            results['seoIssues'].append('Missing viewport meta tag (not mobile-friendly)')

        # Count images and analyze alt text
        images = soup.find_all('img')
        results['details']['images'] = len(images)
        
        # Count links
        links = soup.find_all('a')
        results['details']['links'] = len(links)
        
        # Extract color scheme
        styles = soup.find_all(['style', 'link'])
        colors = set()
        for style in styles:
            if style.string:
                color_matches = re.findall(r'#[0-9a-fA-F]{6}|#[0-9a-fA-F]{3}|rgb\([^)]+\)', style.string)
                colors.update(color_matches)
        results['details']['colorScheme'] = list(colors)[:10]  # Top 10 colors
        
        # Detect technologies and APIs
        scripts = soup.find_all('script')
        apis = set()
        techs = set(['HTML5', 'CSS3'])  # Basic technologies
        
        for script in scripts:
            src = script.get('src', '')
            if 'api' in src.lower():
                apis.add(src)
            for tech in ['React', 'Vue', 'Angular', 'jQuery']:
                if tech.lower() in src.lower():
                    techs.add(tech)
                    
        results['details']['apiEndpoints'] = list(apis)
        results['details']['technologies'] = list(techs)
        
        # Calculate ratings
        security_score = 100 - (len(results['securityIssues']) * 10)  # -10 points per issue
        seo_score = 100 - (len(results['seoIssues']) * 10)  # -10 points per issue
        perf_score = 100 - (results['performance']['responseTime'] / 100)  # Response time impact
        
        results['ratings']['security'] = max(0, min(100, security_score))
        results['ratings']['seo'] = max(0, min(100, seo_score))
        results['ratings']['performance'] = max(0, min(100, perf_score))
        results['ratings']['overall'] = (results['ratings']['security'] + 
                                       results['ratings']['seo'] + 
                                       results['ratings']['performance']) / 3

        # Generate PDF Report
        doc = SimpleDocTemplate('analysis-report.pdf', pagesize=letter)
        styles = getSampleStyleSheet()
        custom_style = ParagraphStyle(
            'CustomStyle',
            parent=styles['Normal'],
            spaceBefore=12,
            spaceAfter=12,
            textColor='#333333'
        )
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Title'],
            textColor='#2C3E50',
            fontSize=24
        )
        story = []

        # Header
        story.append(Paragraph(f'Website Analysis Report', title_style))
        story.append(Paragraph(f'Generated by Web Analyser', custom_style))
        story.append(Paragraph(f'Analysis Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', custom_style))
        story.append(Paragraph(f'Target URL: {url}', custom_style))
        
        # Overall Ratings
        story.append(Paragraph('Overall Ratings', styles['Heading1']))
        story.append(Paragraph(f'Security Score: {results["ratings"]["security"]}%', custom_style))
        story.append(Paragraph(f'SEO Score: {results["ratings"]["seo"]}%', custom_style))
        story.append(Paragraph(f'Performance Score: {results["ratings"]["performance"]}%', custom_style))
        story.append(Paragraph(f'Overall Score: {results["ratings"]["overall"]:.1f}%', custom_style))

        # Performance Details
        story.append(Paragraph('Performance Metrics', styles['Heading1']))
        story.append(Paragraph(f'Response Time: {response_time}ms', custom_style))
        story.append(Paragraph(f'Status Code: {results["performance"]["statusCode"]}', custom_style))
        
        # Technical Details
        story.append(Paragraph('Technical Analysis', styles['Heading1']))
        story.append(Paragraph(f'Number of Images: {results["details"]["images"]}', custom_style))
        story.append(Paragraph(f'Number of Links: {results["details"]["links"]}', custom_style))
        story.append(Paragraph('Detected Technologies:', custom_style))
        for tech in results["details"]["technologies"]:
            story.append(Paragraph(f'• {tech}', custom_style))

        # Security Section
        story.append(Paragraph('Security Analysis', styles['Heading1']))
        if results['securityIssues']:
            for issue in results['securityIssues']:
                story.append(Paragraph(f'• {issue}', custom_style))
        else:
            story.append(Paragraph('No security issues detected', custom_style))

        # SEO Section
        story.append(Paragraph('SEO Analysis', styles['Heading1']))
        if results['seoIssues']:
            for issue in results['seoIssues']:
                story.append(Paragraph(f'• {issue}', custom_style))
        else:
            story.append(Paragraph('No SEO issues detected', custom_style))

        # Recommendations
        story.append(Paragraph('Recommendations', styles['Heading1']))
        story.append(Paragraph('1. Address all security issues to improve website safety', custom_style))
        story.append(Paragraph('2. Implement suggested SEO improvements for better visibility', custom_style))
        story.append(Paragraph('3. Optimize performance if response time exceeds 1000ms', custom_style))
        story.append(Paragraph('4. Regularly monitor and update security headers', custom_style))

        # Footer with contact information
        story.append(Paragraph('Contact Information', styles['Heading2']))
        story.append(Paragraph('Developer: Aditya Choudhry', custom_style))
        story.append(Paragraph('LinkedIn: https://www.linkedin.com/in/aditya-choudhry/', custom_style))
        
        doc.build(story)
        return results

    except Exception as e:
        raise Exception(f'Analysis failed: {str(e)}')

@app.route('/')
def serve_static():
    return send_from_directory('public', 'index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        url = request.json['url']
        results = analyze_website(url)
        return jsonify({
            'message': 'Analysis complete',
            'results': results,
            'reportPath': 'analysis-report.pdf'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/analysis-report.pdf')
def serve_pdf():
    return send_file('analysis-report.pdf')

if __name__ == '__main__':
    try:
        app.run(host='0.0.0.0', port=3000, debug=True)
    except Exception as e:
        print(f"Server failed to start: {e}")
