"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityProvider = void 0;
// ide-plugins/vscode/src/securityProvider.ts
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
class SecurityProvider {
    constructor() {
        this.outputChannel = vscode.window.createOutputChannel('Armadillo DevSecOps');
    }
    /**
     * Scan a single file for security issues
     */
    async scanFile(document) {
        this.outputChannel.show(true);
        this.outputChannel.appendLine(`\n[${new Date().toLocaleTimeString()}] Scanning file: ${document.fileName}`);
        try {
            const issues = await this.performSecurityScan(document);
            if (issues.length === 0) {
                this.outputChannel.appendLine('✓ No security issues found');
                vscode.window.showInformationMessage('No security issues found');
            }
            else {
                this.outputChannel.appendLine(`⚠ Found ${issues.length} security issue(s):`);
                issues.forEach((issue, index) => {
                    this.outputChannel.appendLine(`  ${index + 1}. [${issue.severity}] Line ${issue.line}: ${issue.message}`);
                });
                vscode.window.showWarningMessage(`Found ${issues.length} security issue(s)`);
            }
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            this.outputChannel.appendLine(`✗ Error during scan: ${errorMessage}`);
            vscode.window.showErrorMessage(`Security scan failed: ${errorMessage}`);
        }
    }
    /**
     * Scan the entire workspace for security issues
     */
    async scanWorkspace() {
        this.outputChannel.show(true);
        this.outputChannel.appendLine(`\n[${new Date().toLocaleTimeString()}] Starting workspace scan...`);
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showWarningMessage('No workspace folder open');
            return;
        }
        try {
            // Find all Terraform and YAML files
            const terraformFiles = await vscode.workspace.findFiles('**/*.tf', '**/node_modules/**');
            const yamlFiles = await vscode.workspace.findFiles('**/*.{yaml,yml}', '**/node_modules/**');
            const allFiles = [...terraformFiles, ...yamlFiles];
            this.outputChannel.appendLine(`Found ${allFiles.length} file(s) to scan`);
            let totalIssues = 0;
            for (const fileUri of allFiles) {
                const document = await vscode.workspace.openTextDocument(fileUri);
                const issues = await this.performSecurityScan(document);
                if (issues.length > 0) {
                    totalIssues += issues.length;
                    this.outputChannel.appendLine(`\n${path.basename(fileUri.fsPath)}: ${issues.length} issue(s)`);
                    issues.forEach(issue => {
                        this.outputChannel.appendLine(`  Line ${issue.line}: [${issue.severity}] ${issue.message}`);
                    });
                }
            }
            if (totalIssues === 0) {
                this.outputChannel.appendLine('\n✓ Workspace scan complete: No security issues found');
                vscode.window.showInformationMessage('Workspace scan complete: No issues found');
            }
            else {
                this.outputChannel.appendLine(`\n⚠ Workspace scan complete: Found ${totalIssues} security issue(s)`);
                vscode.window.showWarningMessage(`Workspace scan complete: Found ${totalIssues} issue(s)`);
            }
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            this.outputChannel.appendLine(`✗ Error during workspace scan: ${errorMessage}`);
            vscode.window.showErrorMessage(`Workspace scan failed: ${errorMessage}`);
        }
    }
    /**
     * Perform security scanning on a document
     */
    async performSecurityScan(document) {
        const issues = [];
        const text = document.getText();
        const lines = text.split('\n');
        // Security rules based on file type
        if (document.languageId === 'terraform') {
            issues.push(...this.scanTerraform(lines));
        }
        else if (document.languageId === 'yaml') {
            issues.push(...this.scanYaml(lines));
        }
        return issues;
    }
    /**
     * Scan Terraform files for security issues
     */
    scanTerraform(lines) {
        const issues = [];
        lines.forEach((line, index) => {
            const lineNumber = index + 1;
            const trimmedLine = line.trim();
            // Check for hardcoded secrets
            if (/password\s*=\s*["'][^"']+["']/.test(trimmedLine) ||
                /secret\s*=\s*["'][^"']+["']/.test(trimmedLine) ||
                /api_key\s*=\s*["'][^"']+["']/.test(trimmedLine)) {
                issues.push({
                    line: lineNumber,
                    severity: 'HIGH',
                    message: 'Potential hardcoded secret detected. Use environment variables or secret management.'
                });
            }
            // Check for public access
            if (/publicly_accessible\s*=\s*true/.test(trimmedLine)) {
                issues.push({
                    line: lineNumber,
                    severity: 'MEDIUM',
                    message: 'Resource is publicly accessible. Verify this is intentional.'
                });
            }
            // Check for unencrypted storage
            if (/encrypted\s*=\s*false/.test(trimmedLine)) {
                issues.push({
                    line: lineNumber,
                    severity: 'HIGH',
                    message: 'Encryption is disabled. Enable encryption for sensitive data.'
                });
            }
            // Check for overly permissive CIDR blocks
            if (/cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\]/.test(trimmedLine)) {
                issues.push({
                    line: lineNumber,
                    severity: 'MEDIUM',
                    message: 'Overly permissive CIDR block (0.0.0.0/0). Restrict to specific IP ranges.'
                });
            }
        });
        return issues;
    }
    /**
     * Scan YAML files for security issues
     */
    scanYaml(lines) {
        const issues = [];
        lines.forEach((line, index) => {
            const lineNumber = index + 1;
            const trimmedLine = line.trim();
            // Check for hardcoded secrets in YAML
            if (/(password|secret|api_key|token):\s*["']?[a-zA-Z0-9+/=]{8,}["']?/.test(trimmedLine) &&
                !trimmedLine.includes('$') && !trimmedLine.includes('{{')) {
                issues.push({
                    line: lineNumber,
                    severity: 'HIGH',
                    message: 'Potential hardcoded secret detected. Use secret management or environment variables.'
                });
            }
            // Check for privileged containers
            if (/privileged:\s*true/.test(trimmedLine)) {
                issues.push({
                    line: lineNumber,
                    severity: 'HIGH',
                    message: 'Privileged container detected. Avoid running containers in privileged mode.'
                });
            }
            // Check for host network mode
            if (/hostNetwork:\s*true/.test(trimmedLine)) {
                issues.push({
                    line: lineNumber,
                    severity: 'MEDIUM',
                    message: 'Host network mode enabled. This may expose the host network stack.'
                });
            }
            // Check for missing resource limits
            if (trimmedLine.includes('containers:') || trimmedLine.includes('- name:')) {
                const nextFewLines = lines.slice(index, index + 10).join('\n');
                if (!nextFewLines.includes('resources:') || !nextFewLines.includes('limits:')) {
                    issues.push({
                        line: lineNumber,
                        severity: 'LOW',
                        message: 'Container missing resource limits. Define CPU and memory limits.'
                    });
                }
            }
        });
        return issues;
    }
}
exports.SecurityProvider = SecurityProvider;
//# sourceMappingURL=securityProvider.js.map