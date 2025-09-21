#!/usr/bin/env python3
"""
Simple script to test our DevSecOps setup
"""
import sys
import subprocess
import importlib

def check_python_packages():
    """Check if required Python packages are installed"""
    required_packages = [
        'checkov', 'requests', 'yaml', 'aiohttp', 
        'numpy', 'pandas', 'matplotlib'
    ]
    
    print("🐍 Checking Python packages...")
    all_ok = True
    for package in required_packages:
        try:
            importlib.import_module(package)
            print(f"  ✅ {package} - OK")
        except ImportError:
            print(f"  ❌ {package} - MISSING")
            all_ok = False
    return all_ok

def check_external_tools():
    """Check if external tools are installed"""
    tools = {
        'docker': ['docker', '--version'],
        'docker-compose': ['docker-compose', '--version'], 
        'terraform': ['terraform', '--version'],
        'checkov': ['checkov', '--version'],
        'tfsec': ['tfsec', '--version'],
        'git': ['git', '--version']
    }
    
    print("🔧 Checking external tools...")
    all_ok = True
    for tool_name, command in tools.items():
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"  ✅ {tool_name} - OK")
            else:
                print(f"  ❌ {tool_name} - ERROR")
                all_ok = False
        except FileNotFoundError:
            print(f"  ❌ {tool_name} - NOT FOUND")
            all_ok = False
    return all_ok

def main():
    print("🚀 DevSecOps Setup Verification")
    print("=" * 40)
    
    python_ok = check_python_packages()
    tools_ok = check_external_tools()
    
    print("\n📋 Summary:")
    if python_ok and tools_ok:
        print("  🎉 All checks passed! Your setup is ready.")
        print("  💡 You can now proceed with the framework implementation.")
        return 0
    else:
        print("  ⚠️  Some components are missing. Please review the installation steps.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
