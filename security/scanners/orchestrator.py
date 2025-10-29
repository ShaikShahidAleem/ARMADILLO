# security/scanners/orchestrator.py
import asyncio
import json
from typing import Dict, List, Any
from dataclasses import dataclass
import subprocess
import concurrent.futures

@dataclass
class ScanResult:
    tool: str
    severity: str
    rule_id: str
    description: str
    file_path: str
    line_number: int
    confidence: float

class SecurityOrchestrator:
    def __init__(self, config_path: str = "config/scanner_config.yaml"):
        self.tools = {
            'checkov': CheckovScanner(),
            'tfsec': TfsecScanner(),
            'terrascan': TerrascanScanner(),
            'custom': CustomRuleScanner()
        }
        self.config = self._load_config(config_path)

    async def run_parallel_scans(self, target_path: str) -> Dict[str, List[ScanResult]]:
        """Run all security scanners in parallel"""
        tasks = []
        for tool_name, scanner in self.tools.items():
            if self.config['tools'][tool_name]['enabled']:
                task = asyncio.create_task(scanner.scan(target_path))
                tasks.append((tool_name, task))

        results = {}
        for tool_name, task in tasks:
            try:
                results[tool_name] = await task
            except Exception as e:
                print(f"Error running {tool_name}: {e}")
                results[tool_name] = []

        return results

    def consolidate_results(self, scan_results: Dict[str, List[ScanResult]]) -> List[ScanResult]:
        """Consolidate and deduplicate results from multiple tools"""
        all_results = []
        seen_issues = set()

        for tool, results in scan_results.items():
            for result in results:
                # Create a unique identifier for deduplication
                issue_id = f"{result.file_path}:{result.line_number}:{result.rule_id}"
                if issue_id not in seen_issues:
                    seen_issues.add(issue_id)
                    all_results.append(result)

        # Sort by severity and confidence
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        all_results.sort(key=lambda x: (severity_order.get(x.severity, 999), -x.confidence))

        return all_results