#!/usr/bin/env python3
"""
Simple web dashboard to view security scan results
"""
from flask import Flask, render_template, jsonify
import json
import os
from datetime import datetime

app = Flask(__name__)

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return """
    <html>
    <head>
        <title>DevSecOps Security Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .header { background: #f0f8ff; padding: 20px; border-radius: 5px; }
            .metric { display: inline-block; margin: 10px; padding: 15px; 
                     background: #e6f3ff; border-radius: 5px; min-width: 150px; }
            .critical { background: #ffebee; border-left: 4px solid #f44336; }
            .high { background: #fff3e0; border-left: 4px solid #ff9800; }
            .medium { background: #f3e5f5; border-left: 4px solid #9c27b0; }
            .low { background: #e8f5e8; border-left: 4px solid #4caf50; }
            .finding { margin: 10px 0; padding: 10px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ DevSecOps Security Dashboard</h1>
            <p>Welcome to your security monitoring dashboard!</p>
        </div>
        
        <h2>📊 Quick Metrics</h2>
        <div class="metric">
            <h3>Total Scans</h3>
            <p style="font-size: 24px; margin: 0;">3</p>
        </div>
        <div class="metric">
            <h3>Issues Found</h3>
            <p style="font-size: 24px; margin: 0; color: #f44336;">14</p>
        </div>
        <div class="metric">
            <h3>Issues Fixed</h3>
            <p style="font-size: 24px; margin: 0; color: #4caf50;">6</p>
        </div>
        <div class="metric">
            <h3>Security Score</h3>
            <p style="font-size: 24px; margin: 0; color: #ff9800;">65%</p>
        </div>
        
        <h2>🔍 Recent Findings</h2>
        <div class="finding critical">
            <strong>CRITICAL:</strong> RDS instance has publicly accessible enabled<br>
            <small>File: main.tf | Tool: Checkov</small>
        </div>
        <div class="finding high">
            <strong>HIGH:</strong> S3 Bucket has an ACL defined which allows public access<br>
            <small>File: main.tf | Tool: Checkov</small>
        </div>
        <div class="finding high">
            <strong>HIGH:</strong> Security group rule allows ingress from 0.0.0.0/0<br>
            <small>File: main.tf | Tool: tfsec</small>
        </div>
        
        <h2>💡 Next Steps</h2>
        <ul>
            <li>Fix critical and high severity issues first</li>
            <li>Review security policies for your organization</li>
            <li>Set up automated scanning in your CI/CD pipeline</li>
            <li>Configure alerts for new security findings</li>
        </ul>
        
        <h2>📚 Learning Resources</h2>
        <ul>
            <li><a href="https://docs.aws.amazon.com/security/">AWS Security Best Practices</a></li>
            <li><a href="https://owasp.org/www-project-top-ten/">OWASP Top 10</a></li>
            <li><a href="https://www.checkov.io/1.Welcome/Quick%20Start.html">Checkov Documentation</a></li>
            <li><a href="https://aquasecurity.github.io/tfsec/">tfsec Documentation</a></li>
        </ul>
        
        <footer style="margin-top: 40px; padding: 20px; background: #f5f5f5; text-align: center;">
            <p>🎓 You're on your way to mastering DevSecOps! Keep learning and improving.</p>
        </footer>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)