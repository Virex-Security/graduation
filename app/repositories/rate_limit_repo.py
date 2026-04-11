import os
import time
import logging
import redis
from collections import defaultdict, deque
from app import config

logger = logging.getLogger(__name__)

class RateLimitRepository:
    """Handles rate limiting state in Redis with in-memory fallback."""
    
    def __init__(self):
        self.redis_url = config.redis_url()
        self.redis = None
        self.use_redis = False
        self.rate_limit_storage = defaultdict(deque)
        
        try:
            self.redis = redis.from_url(self.redis_url, decode_responses=True, socket_timeout=2)
            self.redis.ping()
            self.use_redis = True
            logger.info(f"[RL] Connected to Redis at {self.redis_url}")
        except Exception as e:
            logger.warning(f"[RL] Redis connection failed ({e}) — falling back to in-memory")

    def check_and_increment(self, key: str, window: int, limit: int) -> bool:
        """Returns True if within limit, False if exceeded."""
        now = time.time()
        
        if self.use_redis:
            try:
                lua = """
                local key = KEYS[1]
                local now = tonumber(ARGV[1])
                local window = tonumber(ARGV[2])
                local limit = tonumber(ARGV[3])
                
                redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
                local count = redis.call('ZCARD', key)
                
                if count < limit then
                    redis.call('ZADD', key, now, now)
                    redis.call('EXPIRE', key, window)
                    return 1
                else
                    return 0
                end
                """
                return bool(self.redis.register_script(lua)(keys=[key], args=[now, window, limit]))
            except Exception as e:
                logger.error(f"[RL] Redis error: {e}")
                # Fallback to in-memory below
        
        # In-memory fallback
        q = self.rate_limit_storage[key]
        while q and now - q[0] > window:
            q.popleft()
            
        if len(q) >= limit:
            return False
            
        q.append(now)
        return True
