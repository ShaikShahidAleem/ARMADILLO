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
exports.SecurityDiagnosticsProvider = void 0;
// ide-plugins/vscode/src/diagnostics.ts
const vscode = __importStar(require("vscode"));
class SecurityDiagnosticsProvider {
    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('armadillo-security');
    }
    /**
     * Update diagnostics for a document
     */
    async updateDiagnostics(document) {
        if (document.languageId !== 'terraform' && document.languageId !== 'yaml') {
            return;
        }
        const diagnostics = [];
        const text = document.getText();
        const lines = text.split('\n');
        // Analyze based on file type
        if (document.languageId === 'terraform') {
            diagnostics.push(...this.analyzeTerraform(document, lines));
        }
        else if (document.languageId === 'yaml') {
            diagnostics.push(...this.analyzeYaml(document, lines));
        }
        this.diagnosticCollection.set(document.uri, diagnostics);
    }
    /**
     * Analyze Terraform files for security issues
     */
    analyzeTerraform(document, lines) {
        const diagnostics = [];
        lines.forEach((line, index) => {
            const trimmedLine = line.trim();
            // Hardcoded secrets
            if (/password\s*=\s*["'][^"']+["']/.test(trimmedLine) ||
                /secret\s*=\s*["'][^"']+["']/.test(trimmedLine) ||
                /api_key\s*=\s*["'][^"']+["']/.test(trimmedLine)) {
                const range = new vscode.Range(index, 0, index, line.length);
                const diagnostic = new vscode.Diagnostic(range, 'Potential hardcoded secret detected. Use environment variables or secret management systems.', vscode.DiagnosticSeverity.Error);
                diagnostic.source = 'Armadillo Security';
                diagnostic.code = 'HARDCODED_SECRET';
                diagnostics.push(diagnostic);
            }
            // Public access
            if (/publicly_accessible\s*=\s*true/.test(trimmedLine)) {
                const range = new vscode.Range(index, 0, index, line.length);
                const diagnostic = new vscode.Diagnostic(range, 'Resource is publicly accessible. Verify this is intentional and required.', vscode.DiagnosticSeverity.Warning);
                diagnostic.source = 'Armadillo Security';
                diagnostic.code = 'PUBLIC_ACCESS';
                diagnostics.push(diagnostic);
            }
            // Unencrypted storage
            if (/encrypted\s*=\s*false/.test(trimmedLine)) {
                const range = new vscode.Range(index, 0, index, line.length);
                const diagnostic = new vscode.Diagnostic(range, 'Encryption is disabled. Enable encryption for sensitive data at rest.', vscode.DiagnosticSeverity.Error);
                diagnostic.source = 'Armadillo Security';
                diagnostic.code = 'ENCRYPTION_DISABLED';
                diagnostics.push(diagnostic);
            }
            // Overly permissive CIDR blocks
            if (/cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\]/.test(trimmedLine)) {
                const range = new vscode.Range(index, 0, index, line.length);
                const diagnostic = new vscode.Diagnostic(range, 'Overly permissive CIDR block (0.0.0.0/0). Restrict access to specific IP ranges.', vscode.DiagnosticSeverity.Warning);
                diagnostic.source = 'Armadillo Security';
                diagnostic.code = 'PERMISSIVE_CIDR';
                diagnostics.push(diagnostic);
            }
            // Missing encryption for S3 buckets
            if (/resource\s+"aws_s3_bucket"/.test(trimmedLine)) {
                const nextFewLines = lines.slice(index, index + 20).join('\n');
                if (!nextFewLines.includes('server_side_encryption_configuration')) {
                    const range = new vscode.Range(index, 0, index, line.length);
                    const diagnostic = new vscode.Diagnostic(range, 'S3 bucket missing server-side encryption configuration.', vscode.DiagnosticSeverity.Warning);
                    diagnostic.source = 'Armadillo Security';
                    diagnostic.code = 'S3_NO_ENCRYPTION';
                    diagnostics.push(diagnostic);
                }
            }
            // HTTP instead of HTTPS
            if (/protocol\s*=\s*"HTTP"/.test(trimmedLine)) {
                const range = new vscode.Range(index, 0, index, line.length);
                const diagnostic = new vscode.Diagnostic(range, 'Using HTTP instead of HTTPS. Use HTTPS for secure communication.', vscode.DiagnosticSeverity.Warning);
                diagnostic.source = 'Armadillo Security';
                diagnostic.code = 'HTTP_PROTOCOL';
                diagnostics.push(diagnostic);
            }
        });
        return diagnostics;
    }
    /**
     * Analyze YAML files for security issues
     */
    analyzeYaml(document, lines) {
        const diagnostics = [];
        lines.forEach((line, index) => {
            const trimmedLine = line.trim();
            // Hardcoded secrets
            if (/(password|secret|api_key|token):\s*["']?[a-zA-Z0-9+/=]{8,}["']?/.test(trimmedLine) &&
                !trimmedLine.includes('$') && !trimmedLine.includes('{{')) {
                const range = new vscode.Range(index, 0, index, line.length);
                const diagnostic = new vscode.Diagnostic(range, 'Potential hardcoded secret detected. Use Kubernetes secrets or external secret management.', vscode.DiagnosticSeverity.Error);
                diagnostic.source = 'Armadillo Security';
                diagnostic.code = 'HARDCODED_SECRET';
                diagnostics.push(diagnostic);
            }
            // Privileged containers
            if (/privileged:\s*true/.test(trimmedLine)) {
                const range = new vscode.Range(index, 0, index, line.length);
                const diagnostic = new vscode.Diagnostic(range, 'Privileged container detected. Avoid running containers in privileged mode unless absolutely necessary.', vscode.DiagnosticSeverity.Error);
                diagnostic.source = 'Armadillo Security';
                diagnostic.code = 'PRIVILEGED_CONTAINER';
                diagnostics.push(diagnostic);
            }
            // Host network mode
            if (/hostNetwork:\s*true/.test(trimmedLine)) {
                const range = new vscode.Range(index, 0, index, line.length);
                const diagnostic = new vscode.Diagnostic(range, 'Host network mode enabled. This exposes the host network stack to the container.', vscode.DiagnosticSeverity.Warning);
                diagnostic.source = 'Armadillo Security';
                diagnostic.code = 'HOST_NETWORK';
                diagnostics.push(diagnostic);
            }
            // Host path volumes
            if (/hostPath:/.test(trimmedLine)) {
                const range = new vscode.Range(index, 0, index, line.length);
                const diagnostic = new vscode.Diagnostic(range, 'hostPath volume detected. This can expose sensitive host directories to containers.', vscode.DiagnosticSeverity.Warning);
                diagnostic.source = 'Armadillo Security';
                diagnostic.code = 'HOST_PATH';
                diagnostics.push(diagnostic);
            }
            // Run as root
            if (/runAsUser:\s*0/.test(trimmedLine)) {
                const range = new vscode.Range(index, 0, index, line.length);
                const diagnostic = new vscode.Diagnostic(range, 'Container running as root user (UID 0). Use a non-root user for better security.', vscode.DiagnosticSeverity.Warning);
                diagnostic.source = 'Armadillo Security';
                diagnostic.code = 'RUN_AS_ROOT';
                diagnostics.push(diagnostic);
            }
            // Missing security context
            if (trimmedLine.includes('containers:')) {
                const nextFewLines = lines.slice(index, index + 15).join('\n');
                if (!nextFewLines.includes('securityContext:')) {
                    const range = new vscode.Range(index, 0, index, line.length);
                    const diagnostic = new vscode.Diagnostic(range, 'Container missing securityContext. Define security settings for the container.', vscode.DiagnosticSeverity.Information);
                    diagnostic.source = 'Armadillo Security';
                    diagnostic.code = 'MISSING_SECURITY_CONTEXT';
                    diagnostics.push(diagnostic);
                }
            }
            // Missing resource limits
            if (trimmedLine.match(/^\s*-\s*name:/)) {
                const nextFewLines = lines.slice(index, index + 10).join('\n');
                if (!nextFewLines.includes('resources:') || !nextFewLines.includes('limits:')) {
                    const range = new vscode.Range(index, 0, index, line.length);
                    const diagnostic = new vscode.Diagnostic(range, 'Container missing resource limits. Define CPU and memory limits to prevent resource exhaustion.', vscode.DiagnosticSeverity.Information);
                    diagnostic.source = 'Armadillo Security';
                    diagnostic.code = 'MISSING_RESOURCE_LIMITS';
                    diagnostics.push(diagnostic);
                }
            }
        });
        return diagnostics;
    }
    /**
     * Clear all diagnostics
     */
    clear() {
        this.diagnosticCollection.clear();
    }
    /**
     * Dispose of the diagnostic collection
     */
    dispose() {
        this.diagnosticCollection.dispose();
    }
}
exports.SecurityDiagnosticsProvider = SecurityDiagnosticsProvider;
//# sourceMappingURL=diagnostics.js.map