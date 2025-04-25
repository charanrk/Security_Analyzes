from flask import Blueprint, render_template, request, jsonify, current_app, redirect, url_for, flash, session
from flask_login import login_required, current_user
from ..utils.file_scanner import FileScanner
import os
from werkzeug.utils import secure_filename
import hashlib
import requests
from datetime import datetime

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/analyze-url', methods=['POST'])
@login_required
def analyze_url():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return jsonify({'error': 'Failed to fetch URL'}), 400
            
        headers = dict(response.headers)
        
        # Basic security checks
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options', 'Not Set'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not Set'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not Set'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not Set'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not Set')
        }
        
        return jsonify({
            'url': url,
            'status': response.status_code,
            'headers': security_headers,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main_bp.route('/check-hash', methods=['POST'])
@login_required
def check_hash():
    hash_value = request.form.get('hash')
    hash_type = request.form.get('type', 'sha256')
    
    if not hash_value:
        return jsonify({'error': 'Hash value is required'}), 400
    
    try:
        # Check hash against VirusTotal
        vt_api_key = os.getenv('VIRUS_TOTAL_API_KEY')
        if vt_api_key:
            headers = {'x-apikey': vt_api_key}
            url = f'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'resource': hash_value}
            
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                return jsonify({
                    'hash': hash_value,
                    'type': hash_type,
                    'reputation': {
                        'status': 'malicious' if data.get('positives', 0) > 0 else 'clean',
                        'confidence': data.get('positives', 0) / data.get('total', 1) * 100,
                        'sources': [{'name': 'VirusTotal', 'result': data}]
                    },
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        return jsonify({
            'hash': hash_value,
            'type': hash_type,
            'reputation': {
                'status': 'unknown',
                'confidence': 0,
                'sources': []
            },
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main_bp.route('/scan-file', methods=['POST'])
def scan_file():
    current_app.logger.info("File upload request received")
    
    if 'file' not in request.files:
        current_app.logger.error("No file part in request")
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        current_app.logger.error("No selected file")
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        # Log file details
        current_app.logger.info(f"Processing file: {file.filename} ({file.content_type})")
        
        filename = secure_filename(file.filename)
        upload_dir = os.path.join(current_app.instance_path, 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        
        current_app.logger.info(f"Upload directory: {upload_dir}")
        
        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)
        
        if not os.path.exists(file_path):
            current_app.logger.error(f"Failed to save file to {file_path}")
            return jsonify({'error': 'Failed to save uploaded file'}), 500
            
        file_size = os.path.getsize(file_path)
        current_app.logger.info(f"File saved successfully. Size: {file_size} bytes")
        
        scanner = FileScanner()
        result = scanner.scan_file(file_path)
        current_app.logger.info("File scan completed successfully")
        
        # Store scan results in session
        scan_data = {
            'filename': filename,
            'filesize': file_size,
            'scan_results': result,
            'timestamp': datetime.utcnow().isoformat()
        }
        session['pending_scan_results'] = scan_data
        
        # Clean up the uploaded file
        try:
            os.remove(file_path)
            current_app.logger.info("Temporary file removed")
        except Exception as e:
            current_app.logger.error(f"Error removing uploaded file: {e}")
        
        if not current_user.is_authenticated:
            # If user is not logged in, redirect to login page
            return jsonify({
                'status': 'redirect',
                'redirect': url_for('auth.login'),
                'message': 'Please login to view scan results'
            })
        else:
            # If user is logged in, store results and redirect to results page
            session['last_file_scan'] = scan_data
            session.pop('pending_scan_results', None)  # Remove from pending
            return jsonify({
                'status': 'success',
                'redirect': url_for('main.file_scan_results')
            })
        
    except Exception as e:
        current_app.logger.error(f"Error during file scan: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@main_bp.route('/file-scan-results')
@login_required
def file_scan_results():
    # Check for pending results first
    pending_results = session.get('pending_scan_results')
    if pending_results:
        # Move pending results to last_file_scan
        session['last_file_scan'] = pending_results
        session.pop('pending_scan_results', None)
        return render_template('file_scan_results.html', results=pending_results)
    
    # Check for existing results
    scan_results = session.get('last_file_scan')
    if not scan_results:
        flash('No file scan results available. Please scan a file first.', 'warning')
        return redirect(url_for('main.index'))
    
    return render_template('file_scan_results.html', results=scan_results) 