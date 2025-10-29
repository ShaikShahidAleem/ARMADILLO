# tests/load/load_testing_suite.py
import asyncio
import aiohttp
import time
import statistics
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class LoadTestConfig:
    name: str
    url: str
    method: str
    headers: Dict[str, str]
    payload: Dict[str, Any]
    concurrent_users: int
    duration_seconds: int
    ramp_up_seconds: int

@dataclass
class LoadTestResult:
    timestamp: float
    response_time: float
    status_code: int
    error: str = None
    success: bool = True

class LoadTestRunner:
    def __init__(self):
        self.results: List[LoadTestResult] = []

    async def run_load_test(self, config: LoadTestConfig) -> Dict[str, Any]:
        # ... implementation to simulate users and gather results
        return self._analyze_results(config)

    async def _simulate_user(self, config: LoadTestConfig, semaphore: asyncio.Semaphore, delay: float, user_id: int):
        # ... simulates a single user's session
        pass

    async def _make_request(self, config: LoadTestConfig, session: aiohttp.ClientSession, user_id: int):
        # ... makes a single HTTP request and records the result
        pass

    def _analyze_results(self, config: LoadTestConfig) -> Dict[str, Any]:
        # ... calculates summary statistics (avg response time, RPS, etc.)
        analysis = {}
        return analysis