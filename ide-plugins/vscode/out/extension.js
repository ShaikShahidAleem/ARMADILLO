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
exports.activate = activate;
// ide-plugins/vscode/src/extension.ts
const vscode = __importStar(require("vscode"));
const securityProvider_1 = require("./securityProvider");
const diagnostics_1 = require("./diagnostics");
function activate(context) {
    const securityProvider = new securityProvider_1.SecurityProvider();
    const diagnosticsProvider = new diagnostics_1.SecurityDiagnosticsProvider();
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
    context.subscriptions.push(scanCommand, scanWorkspaceCommand, onSaveHandler, statusBarItem);
}
//# sourceMappingURL=extension.js.map