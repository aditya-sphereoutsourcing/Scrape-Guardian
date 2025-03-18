
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

app = Flask(__name__, static_folder='../frontend', static_url_path='')

def check_response_time(url):
    start_time = time.time()
    response = requests.get(url)
    end_time = time.time()
    return round((end_time - start_time) * 1000)

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
    # Your existing analyze_website function here
    # (keeping the same implementation as in main.py)
    pass

@app.route('/')
def serve_static():
    return send_from_directory('../frontend', 'index.html')

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
    app.run(host='0.0.0.0', port=3000, debug=True)
