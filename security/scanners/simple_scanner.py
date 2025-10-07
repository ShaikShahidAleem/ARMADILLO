#!/usr/bin/env python3
"""
Simple security scanner to get started with DevSecOps
"""
import os
import sys
import subprocess
import json
from typing import List, Dict

class SimpleSecurityScanner:
    def __init__(self, project_path: str):
        self.project_path = project_path
        self.results = {}
    def run_checkov_scan(self) -> Dict:
        """Run Checkov security scan"""
        print("Running Checkov scan...")
        
        try:
            cmd = [
                'checkov', 
                '-d', self.project_path,
                '--framework', 'terraform',
                '--output', 'json',
                '--quiet'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            # Checkov returns exit code 1 when it finds issues, so check stdout first
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    return {
                        'tool': 'checkov',
                        'status': 'success',
                        'findings': data.get('results', {}).get('failed_checks', []),
                        'passed_checks': data.get('results', {}).get('passed_checks', [])
                    }
                except json.JSONDecodeError as e:
                    return {
                        'tool': 'checkov',
                        'status': 'error',
                        'error': f'Failed to parse JSON output: {str(e)}',
                        'findings': []
                    }
            
            return {
                'tool': 'checkov',
                'status': 'error',
                'error': result.stderr if result.stderr else 'No output from checkov',
                'findings': []
            }
            
        except Exception as e:
            return {
                'tool': 'checkov',
                'status': 'error',
                'error': str(e),
                'findings': []
            }
    
    def run_tfsec_scan(self) -> Dict:
        """Run tfsec security scan"""
        print("Running tfsec scan...")
        
        try:
            cmd = [
                'tfsec',
                self.project_path,
                '--format', 'json',
                '--soft-fail'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    return {
                        'tool': 'tfsec',
                        'status': 'success',
                        'findings': data.get('results', [])
                    }
                except json.JSONDecodeError:
                    pass
            
            # If no JSON output, tfsec might have found no issues
            return {
                'tool': 'tfsec',
                'status': 'success',
                'findings': []
            }
            
        except Exception as e:
            return {
                'tool': 'tfsec',
                'status': 'error',
                'error': str(e),
                'findings': []
            }
    
    def run_all_scans(self) -> Dict:
        """Run all available security scans"""
        print(f"🚀 Starting security scan of: {self.project_path}")
        print("=" * 50)
        
        results = {}
        
        # Run Checkov
        results['checkov'] = self.run_checkov_scan()
        
        # Run tfsec
        results['tfsec'] = self.run_tfsec_scan()
        
        return results
    
    def print_summary(self, results: Dict):
        """Print a human-readable summary of results"""
        print("\n📊 SECURITY SCAN SUMMARY")
        print("=" * 50)
        
        total_findings = 0
        
        for tool_name, tool_results in results.items():
            print(f"\n🔧 {tool_name.upper()} Results:")
            
            if tool_results['status'] == 'error':
                print(f"  ❌ Error: {tool_results.get('error', 'Unknown error')}")
                continue
            
            findings = tool_results.get('findings', [])
            findings_count = len(findings)
            total_findings += findings_count
            
            if findings_count == 0:
                print("  ✅ No security issues found!")
            else:
                print(f"  ⚠️  Found {findings_count} security issues:")
                
                # Group findings by severity
                severity_counts = {}
                for finding in findings[:5]:  # Show first 5 findings
                    if tool_name == 'checkov':
                        severity = finding.get('severity', 'UNKNOWN')
                        check_name = finding.get('check_name', 'Unknown check')
                        file_path = finding.get('file_path', 'Unknown file')
                        print(f"    - {severity}: {check_name} in {file_path}")
                    elif tool_name == 'tfsec':
                        severity = finding.get('severity', 'UNKNOWN')
                        rule_desc = finding.get('description', 'Unknown issue')
                        location = finding.get('location', {}).get('filename', 'Unknown file')
                        print(f"    - {severity}: {rule_desc} in {location}")
                    
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                if findings_count > 5:
                    print(f"    ... and {findings_count - 5} more issues")
        
        print(f"\n🎯 TOTAL FINDINGS: {total_findings}")
        
        if total_findings == 0:
            print("🎉 Congratulations! No security issues found.")
        else:
            print("💡 Review these issues and fix them to improve security.")
        
        print("\n" + "=" * 50)

def main():
    if len(sys.argv) != 2:
        print("Usage: python simple_scanner.py <path_to_scan>")
        sys.exit(1)
    
    scan_path = sys.argv[1]
    
    if not os.path.exists(scan_path):
        print(f"Error: Path '{scan_path}' does not exist")
        sys.exit(1)
    
    scanner = SimpleSecurityScanner(scan_path)
    results = scanner.run_all_scans()
    scanner.print_summary(results)

if __name__ == "__main__":
    main()


# Make it executable
#chmod +x security/scanners/simple_scanner.py