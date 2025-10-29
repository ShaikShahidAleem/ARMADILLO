// ide-plugins/vscode/src/extension.ts
import * as vscode from 'vscode';
import { SecurityProvider } from "./securityProvider";
import { SecurityDiagnosticsProvider } from "./diagnostics";

export function activate(context: vscode.ExtensionContext) {
    const securityProvider = new SecurityProvider();
    const diagnosticsProvider = new SecurityDiagnosticsProvider();
    
    // Register commands
    const scanCommand = vscode.commands.registerCommand('devsecops.scanFile', async () => {
        const activeEditor = vscode.window.activeTextEditor;
        if (activeEditor) {
            await securityProvider.scanFile(activeEditor.document);
        }
    });
    
    const scanWorkspaceCommand = vscode.commands.registerCommand('devsecops.scanWorkspace', async () => {
        await securityProvider.scanWorkspace();
    });
    
    // Real-time scanning on save
    const onSaveHandler = vscode.workspace.onDidSaveTextDocument(async (document) => {
        if (document.languageId === 'terraform' || document.languageId === 'yaml') {
            await diagnosticsProvider.updateDiagnostics(document);
        }
    });
    
    // Status bar item
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'devsecops.scanFile';
    statusBarItem.text = '$(shield) DevSecOps';
    statusBarItem.tooltip = 'Click to run security scan';
    statusBarItem.show();
    
    context.subscriptions.push(
        scanCommand,
        scanWorkspaceCommand,
        onSaveHandler,
        statusBarItem
    );
}