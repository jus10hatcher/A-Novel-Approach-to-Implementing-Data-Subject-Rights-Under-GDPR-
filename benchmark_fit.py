"""benchmark_fit.py
Minimal helpers to encode vendor/industry benchmark medians/p95 into parameters
for simple log-normal / gamma sampling used by the simulator.
No external data: call `register_latency` etc. with known values.
"""
from __future__ import annotations
import math

class BenchCatalog:
    def __init__(self):
        self.latency_params = {}  # (system,right,load) -> (mu, sigma) for lognormal
        self.tps_params = {}      # (system,load) -> (shape, scale) for gamma
    
    @staticmethod
    def _fit_lognormal_from_median_p95(median_ms: float, p95_ms: float):
        # Solve for mu, sigma given median and 95th percentile of a lognormal
        # median = exp(mu); p95 = exp(mu + 1.64485*sigma)
        mu = math.log(median_ms)
        sigma = max(1e-9, (math.log(p95_ms) - mu) / 1.64485)
        return mu, sigma
    
    @staticmethod
    def _fit_gamma_from_mean_var(mean_x)
