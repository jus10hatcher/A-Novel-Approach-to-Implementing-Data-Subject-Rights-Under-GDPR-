"""run_sim.py
Main simulation loop calibrated by benchmark_fit.BenchCatalog.
Emulates rights requests and computes Compliance Success and metrics.
"""
from __future__ import annotations
import math, random, time
from typing import Dict, Tuple
from benchmark_fit import BenchCatalog
from synthetic_data import batch

RNG = random.Random(123)

RIGHTS = ['Access','Rectification','Erasure','Restriction','Portability']
SYSTEMS = ['Vaultless','Vaulted','Encryption']

SLO = {
    'Access': (500, 1500),
    'Rectification': (600, 2000),
    'Erasure': (1000, 3000),
    'Restriction': (500, 1500),
    'Portability': (1200, 2500),
}

def sample_latency_ms(cat: BenchCatalog, system: str, right: str, load: int) -> float:
    mu, sigma = cat.latency_params[(system,right,load)]
    # lognormal sample
    z = RNG.gauss(0, 1)
    return math.exp(mu + sigma*z)

def authorized_attempt_blocked(prob_block: fl
A.4 analysis_glmm.py (excerpt)
"""analysis_glmm.py
Skeleton for GLMM/ANOVA analysis using statsmodels / scipy.
(Note: In the dissertation, results will be produced from the collected CSV/Parquet.)
"""
# Pseudocode only; replace with concrete data paths
# import pandas as pd
# import statsmodels.api as sm
# import statsmodels.formula.api as smf

# df = pd.read_csv('results.csv')
# # Example: GLMM for compliance (binary)
# model = smf.glm('compliance_success ~ C(system)*C(right)*C(load)',
#                 data=df, family=sm.families.Binomial()).fit()
# print(model.summary())
#
# # Mixed ANOVA for latency (log transform)
# df
