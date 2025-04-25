from flask import Blueprint, jsonify, request, send_file
from flask_login import login_required, current_user
import json
import pdfkit
import os
from datetime import datetime
import io
from ..utils.file_scanner import FileScanner

api_bp = Blueprint('api', __name__)

@api_bp.route('/export/pdf', methods=['POST'])
@login_required
def export_pdf():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Generate PDF content
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #333; }}
                .section {{ margin: 20px 0; }}
                .result {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>Security Analysis Report</h1>
            <div class="section">
                <h2>Analysis Details</h2>
                <div class="result">
                    <pre>{json.dumps(data, indent=2)}</pre>
                </div>
            </div>
            <div class="section">
                <p>Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
        </body>
        </html>
        """
        
        # Convert HTML to PDF
        pdf = pdfkit.from_string(html_content, False)
        
        # Create a BytesIO object
        pdf_io = io.BytesIO(pdf)
        
        return send_file(
            pdf_io,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'security_report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.pdf'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/export/text', methods=['POST'])
@login_required
def export_text():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Generate text report
        text_content = f"""
Security Analysis Report
=======================
Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

Analysis Details:
----------------
{json.dumps(data, indent=2)}
"""
        
        # Create a BytesIO object
        text_io = io.BytesIO(text_content.encode())
        
        return send_file(
            text_io,
            mimetype='text/plain',
            as_attachment=True,
            download_name=f'security_report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.txt'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/check-reputation/<hash_value>')
@login_required
def check_reputation(hash_value):
    try:
        scanner = FileScanner()
        result = scanner.check_file_reputation(hash_value)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500 