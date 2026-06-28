import time
import psutil
import os
import random

os.environ['DATABASE_URL'] = 'sqlite:///data/virex.db'

from app.ml.inference import ml_analyze, _ensure_ml_ready

def run_benchmark():
    _ensure_ml_ready()
    
    # Generate some random payloads simulating normal traffic and attacks
    payloads = [
        "hello world",
        "SELECT * FROM users",
        "<script>alert(1)</script>",
        "admin' OR 1=1--",
        "just a normal comment here",
        "http://169.254.169.254/latest/meta-data/",
        "A" * 1000,
        "something normal",
        "another normal string",
        "12345"
    ] * 100 # 1000 requests total
    
    for i in range(len(payloads)):
        payloads[i] = payloads[i] + str(i % 10) 

    print("Starting benchmark for 1000 requests...")
    
    # Warmup
    ml_analyze("warmup")
    
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / (1024 * 1024)
    
    start_time = time.time()
    for p in payloads:
        ml_analyze(p, async_feedback=False)
    end_time = time.time()
    
    mem_after = process.memory_info().rss / (1024 * 1024)
    
    latency = end_time - start_time
    avg_latency = (latency / len(payloads)) * 1000
    
    print(f"Total time: {latency:.4f} seconds")
    print(f"Average latency: {avg_latency:.4f} ms per request")
    print(f"Memory used during loop: {mem_after - mem_before:.2f} MB")
    print(f"Total memory: {mem_after:.2f} MB")

if __name__ == "__main__":
    run_benchmark()
