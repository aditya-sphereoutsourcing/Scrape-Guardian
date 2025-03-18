
from flask import Flask, request, jsonify, send_file, send_from_directory
import requests
from bs4 import BeautifulSoup
import logging
import time
import urllib.parse
import ssl
import socket
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='../frontend', static_url_path='')

class SecurityTester:
    @staticmethod
    def test_xss(url, payload="<script>alert('XSS')</script>"):
        logger.debug(f"Testing XSS vulnerability for URL: {url}")
        try:
            params = {"search": payload}
            response = requests.get(url, params=params)
            is_vulnerable = payload in response.text
            logger.debug(f"XSS test result: {'Vulnerable' if is_vulnerable else 'Not vulnerable'}")
            return is_vulnerable
        except Exception as e:
            logger.error(f"XSS test error: {str(e)}")
            return False

    @staticmethod
    def test_sql_injection(url, param="id"):
        logger.debug(f"Testing SQL injection for URL: {url}")
        payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
        try:
            for payload in payloads:
                params = {param: payload}
                response = requests.get(url, params=params)
                if "SQL" in response.text or "syntax error" in response.text.lower():
                    logger.debug("SQL injection vulnerability detected")
                    return True
            logger.debug("No SQL injection vulnerability detected")
            return False
        except Exception as e:
            logger.error(f"SQL injection test error: {str(e)}")
            return False

class PerformanceTester:
    @staticmethod
    def check_response_time(url):
        logger.debug(f"Checking response time for URL: {url}")
        start_time = time.time()
        response = requests.get(url)
        end_time = time.time()
        response_time = round((end_time - start_time) * 1000)
        logger.debug(f"Response time: {response_time}ms")
        return response_time

    @staticmethod
    def check_ssl(url):
        logger.debug(f"Checking SSL for URL: {url}")
        hostname = urllib.parse.urlparse(url).hostname
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssl_info = {
                        'valid': True,
                        'version': ssock.version(),
                        'expiry': datetime.fromtimestamp(ssl.cert_time_to_seconds(ssock.getpeercert()['notAfter']))
                    }
                    logger.debug(f"SSL check result: {ssl_info}")
                    return ssl_info
        except Exception as e:
            logger.error(f"SSL check error: {str(e)}")
            return {'valid': False}

class WebsiteAnalyzer:
    def __init__(self):
        self.security_tester = SecurityTester()
        self.performance_tester = PerformanceTester()

    def analyze(self, url):
        logger.info(f"Starting analysis for URL: {url}")
        results = {
            "performance": {},
            "security": {},
            "details": {},
            "securityIssues": [],
            "seoIssues": [],
            "ratings": {
                "security": 0,
                "seo": 0,
                "performance": 0,
                "overall": 0
            }
        }

        try:
            # Performance checks
            response_time = self.performance_tester.check_response_time(url)
            results["performance"]["responseTime"] = response_time

            # Security checks
            security_score = 100
            
            # XSS Check
            if self.security_tester.test_xss(url):
                security_score -= 20
                results["securityIssues"].append("Potential XSS vulnerability detected")

            # SQL Injection Check
            if self.security_tester.test_sql_injection(url):
                security_score -= 20
                results["securityIssues"].append("Potential SQL injection vulnerability detected")

            # SSL Check
            ssl_info = self.performance_tester.check_ssl(url)
            if not ssl_info['valid']:
                security_score -= 30
                results["securityIssues"].append("Invalid or missing SSL certificate")

            # Calculate final scores
            results["ratings"]["security"] = max(0, security_score)
            results["ratings"]["performance"] = max(0, 100 - (response_time / 100))
            results["ratings"]["overall"] = (
                results["ratings"]["security"] +
                results["ratings"]["performance"]
            ) / 2

            logger.info("Analysis completed successfully")
            return results

        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            return {"error": str(e)}

analyzer = WebsiteAnalyzer()

@app.route('/')
def serve_static():
    return send_from_directory('../frontend', 'index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        url = request.json['url']
        logger.info(f"Received analysis request for URL: {url}")
        results = analyzer.analyze(url)
        return jsonify({
            'message': 'Analysis complete',
            'results': results
        })
    except Exception as e:
        logger.error(f"Analysis request failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)
