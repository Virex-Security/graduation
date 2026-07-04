import sys
import os

sys.path.append(os.path.join(os.getcwd(), 'backend'))

from app.dashboard.services import SecurityDashboard

sd = SecurityDashboard()
metrics = sd.compute_ml_metrics()
print(metrics)
