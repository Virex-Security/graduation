"""
ML Inference Module - Advanced Multi-Class Threat Detection Engine v2
======================================================================
Decision Engine:
  >= THRESHOLD_BLOCK   → block
  >= THRESHOLD_MONITOR → monitor
  else                 → allow

Attack Classes:
  0 normal            5 ssrf
  1 sql_injection     6 xxe
  2 xss               7 ssti
  3 command_injection 8 log4shell
  4 path_traversal    9 brute_force
"""

import os, re, sys, time, json, hashlib, logging, threading, joblib
import pandas as pd, numpy as np
from pathlib import Path
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

PROJECT_ROOT     = Path(__file__).parent.parent.parent
DATA_DIR         = PROJECT_ROOT / "data"
MODEL_V2_PATH    = DATA_DIR / "model_v2.pkl"
VEC_V2_PATH      = DATA_DIR / "vectorizer_v2.pkl"
SEC_FEAT_V2_PATH = DATA_DIR / "sec_features_v2.pkl"
LE_V2_PATH       = DATA_DIR / "label_encoder_v2.pkl"
MODEL_PATH       = DATA_DIR / "model.pkl"
VECTORIZER_PATH  = DATA_DIR / "vectorizer.pkl"
TRAINING_DATA_PATH = DATA_DIR / ("ml_training_data_v2.csv" if (DATA_DIR/"ml_training_data_v2.csv").exists() else "ml_training_data.csv")
FEEDBACK_LOG_PATH  = DATA_DIR / "ml_feedback.json"
PRED_LOG_PATH      = DATA_DIR / "predictions_log.jsonl"

RETRAIN_INTERVAL = int(os.getenv("ML_RETRAIN_INTERVAL","3600"))
CACHE_SIZE       = int(os.getenv("ML_CACHE_SIZE","1024"))
CACHE_TTL        = int(os.getenv("ML_CACHE_TTL","300"))
THRESHOLD_BLOCK  = float(os.getenv("ML_THRESHOLD_BLOCK","0.85"))
THRESHOLD_MONITOR= float(os.getenv("ML_THRESHOLD_MONITOR","0.60"))
LOG_PREDICTIONS  = os.getenv("ML_LOG_PREDICTIONS","false").lower()=="true"

SEVERITY_MAP = {
    "log4shell":"critical","command_injection":"critical",
    "sql_injection":"high","ssrf":"high","xxe":"high","ssti":"high",
    "xss":"medium","path_traversal":"medium",
    "brute_force":"low","normal":"none","attack":"medium","unknown":"none",
}

_model=None; _vectorizer=None; _sec_feat=None; _label_enc=None
_model_version="v1"; _model_lock=threading.RLock()
MODEL_LOADED=False; _using_v2=False

class _LRUCache:
    def __init__(self,max_size=CACHE_SIZE,ttl=CACHE_TTL):
        self._cache=OrderedDict(); self._max=max_size; self._ttl=ttl
        self._lock=threading.Lock(); self._hits=0; self._misses=0
    def _key(self,t): return hashlib.md5(t.encode("utf-8",errors="replace")).hexdigest()
    def get(self,t):
        k=self._key(t)
        with self._lock:
            if k in self._cache:
                val,ts=self._cache[k]
                if time.time()-ts<self._ttl:
                    self._cache.move_to_end(k); self._hits+=1; return val
                del self._cache[k]
            self._misses+=1; return None
    def set(self,t,v):
        k=self._key(t)
        with self._lock:
            self._cache[k]=(v,time.time()); self._cache.move_to_end(k)
            if len(self._cache)>self._max: self._cache.popitem(last=False)
    def clear(self):
        with self._lock: self._cache.clear()
    @property
    def stats(self):
        with self._lock:
            tot=self._hits+self._misses
            return {"hits":self._hits,"misses":self._misses,
                    "hit_rate":round(self._hits/tot,3) if tot else 0,
                    "cache_size":len(self._cache)}

_cache=_LRUCache()
_executor=ThreadPoolExecutor(max_workers=4,thread_name_prefix="ml_worker")
_feedback_lock=threading.Lock(); _pred_log_lock=threading.Lock()

def _append_feedback(text,risk_score,decision,attack_type):
    sanitized=re.sub(r'(?i)(password|passwd|pwd|token|secret|key|auth)=[^\s&"]+',r'\1=***REDACTED***',text)
    entry={"timestamp":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
           "text_hash":hashlib.md5(text.encode("utf-8",errors="replace")).hexdigest(),
           "text_snippet":sanitized[:120],"risk_score":risk_score,
           "decision":decision,"attack_type":attack_type,"reviewed":False,"promoted_to_rule":False}
    try:
        with _feedback_lock:
            existing=[]
            if FEEDBACK_LOG_PATH.exists():
                try:
                    with open(FEEDBACK_LOG_PATH,"r",encoding="utf-8") as f: existing=json.load(f)
                except: existing=[]
            existing.append(entry)
            if len(existing)>5000: existing=existing[-5000:]
            DATA_DIR.mkdir(parents=True,exist_ok=True)
            with open(FEEDBACK_LOG_PATH,"w",encoding="utf-8") as f: json.dump(existing,f,indent=2,ensure_ascii=False)
    except Exception as e: logger.error(f"[ML-FEEDBACK] write failed: {e}")

def _log_prediction(text_hash,confidence,attack_type,severity,action,model_ver):
    if not LOG_PREDICTIONS: return
    entry={"ts":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"text_hash":text_hash,
           "predicted":attack_type,"confidence":confidence,"severity":severity,
           "action":action,"model_version":model_ver}
    try:
        with _pred_log_lock:
            DATA_DIR.mkdir(parents=True,exist_ok=True)
            with open(PRED_LOG_PATH,"a",encoding="utf-8") as f: f.write(json.dumps(entry,ensure_ascii=False)+"\n")
    except Exception as e: logger.error(f"[ML-PRED-LOG] {e}")

def _try_load_v2():
    global _model,_vectorizer,_sec_feat,_label_enc,MODEL_LOADED,_using_v2,_model_version
    if all(p.exists() for p in [MODEL_V2_PATH,VEC_V2_PATH,SEC_FEAT_V2_PATH,LE_V2_PATH]):
        try:
            sys.path.insert(0,str(PROJECT_ROOT))
            with _model_lock:
                _model=joblib.load(str(MODEL_V2_PATH)); _vectorizer=joblib.load(str(VEC_V2_PATH))
                _sec_feat=joblib.load(str(SEC_FEAT_V2_PATH)); _label_enc=joblib.load(str(LE_V2_PATH))
                MODEL_LOADED=True; _using_v2=True; _model_version="v2.0"
            logger.info("[ML] v2 multi-class model loaded"); return True
        except Exception as e: logger.warning(f"[ML] v2 load failed: {e}")
    return False

def _try_load_v1():
    global _model,_vectorizer,MODEL_LOADED,_using_v2,_model_version
    try:
        with _model_lock:
            _model=joblib.load(str(MODEL_PATH)); _vectorizer=joblib.load(str(VECTORIZER_PATH))
            MODEL_LOADED=True; _using_v2=False; _model_version="v1.0"
        logger.info("[ML] v1 fallback model loaded"); return True
    except: return False

def _retrain_v1():
    global _model,_vectorizer,MODEL_LOADED,_using_v2,_model_version
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.model_selection import train_test_split
    try:
        data=pd.read_csv(str(TRAINING_DATA_PATH))
        y=data["label"] if "label" in data.columns else (data["attack_type"]!="normal").astype(int)
        Xtr,Xte,ytr,yte=train_test_split(data["text"],y,test_size=0.2,random_state=42,stratify=y)
        vec=TfidfVectorizer(ngram_range=(1,2),max_features=10000,analyzer="char_wb",sublinear_tf=True)
        clf=RandomForestClassifier(n_estimators=150,max_depth=20,random_state=42,n_jobs=-1)
        clf.fit(vec.fit_transform(Xtr),ytr)
        with _model_lock:
            _model=clf; _vectorizer=vec; MODEL_LOADED=True; _using_v2=False; _model_version="v1.0-auto"
        DATA_DIR.mkdir(parents=True,exist_ok=True)
        joblib.dump(clf,str(MODEL_PATH)); joblib.dump(vec,str(VECTORIZER_PATH))
        from sklearn.metrics import accuracy_score
        logger.info(f"[ML] v1 retrained — Acc: {accuracy_score(yte,clf.predict(vec.transform(Xte)))*100:.2f}%")
    except Exception as e: logger.error(f"[ML] retrain failed: {e}")

def _load_or_train():
    if _try_load_v2(): return
    if _try_load_v1(): return
    logger.warning("[ML] No model — training v1 from scratch...")
    _retrain_v1()

def _auto_retrain_loop():
    while True:
        time.sleep(RETRAIN_INTERVAL); logger.info("[ML] Auto-retraining...")
        if not _try_load_v2(): _retrain_v1()
        _cache.clear()

def _compute_v2(text):
    from scipy.sparse import hstack
    with _model_lock:
        Xf=hstack([_vectorizer.transform([text]),_sec_feat.transform([text])])
        proba=_model.predict_proba(Xf)[0]
        pred_idx=int(np.argmax(proba))
    classes=list(_label_enc.classes_)
    attack_type=classes[pred_idx]; confidence=float(proba[pred_idx])
    normal_idx=classes.index("normal") if "normal" in classes else -1
    risk_score=1.0-float(proba[normal_idx]) if normal_idx>=0 else confidence
    class_probs={cls:round(float(p),4) for cls,p in zip(classes,proba)}
    return risk_score,attack_type,confidence,class_probs

def _compute_v1(text):
    with _model_lock:
        X=_vectorizer.transform([text])
        if hasattr(_model,"predict_proba"):
            proba=_model.predict_proba(X)[0]; classes=list(_model.classes_)
            idx=classes.index(1) if 1 in classes else -1
            risk=float(proba[idx]) if idx>=0 else 0.0
        else:
            risk=1.0 if _model.predict(X)[0]==1 else 0.0
    attack_type=_classify_v1(text)
    return risk,attack_type,risk,{attack_type:risk}

def _classify_v1(text):
    t=text.lower()
    if re.search(r"(select|insert|update|delete|drop|union|exec|sleep|benchmark|waitfor)",t): return "sql_injection"
    if re.search(r"(<script|javascript:|onerror|onload|onclick|<iframe|<svg|alert\()",t): return "xss"
    if re.search(r"(;|\||`|&&|\|\|)\s*(cat|ls|rm|wget|curl|nc|bash|sh|python)",t): return "command_injection"
    if re.search(r"(\.\./|\.\.\\|%2e%2e|etc/passwd|etc/shadow|proc/self)",t): return "path_traversal"
    if re.search(r"\$\{jndi:",t): return "log4shell"
    if re.search(r"(127\.0\.0\.1|localhost|169\.254\.169\.254)",t): return "ssrf"
    if re.search(r"(password|login|user|admin)",t): return "brute_force"
    return "attack"

def _make_decision(risk_score):
    if risk_score>=THRESHOLD_BLOCK: return "block"
    if risk_score>=THRESHOLD_MONITOR: return "monitor"
    return "allow"

class MLDecision:
    __slots__=("risk_score","action","attack_type","attack_class_id",
               "confidence","severity","class_probabilities","from_cache","model_version")
    def __init__(self,risk_score,action,attack_type,attack_class_id=0,
                 confidence=0.0,severity="none",class_probabilities=None,
                 from_cache=False,model_version="v1.0"):
        self.risk_score=risk_score; self.action=action; self.attack_type=attack_type
        self.attack_class_id=attack_class_id; self.confidence=confidence
        self.severity=severity; self.class_probabilities=class_probabilities or {}
        self.from_cache=from_cache; self.model_version=model_version
    @property
    def should_block(self): return self.action=="block"
    @property
    def should_monitor(self): return self.action in ("block","monitor")
    def to_dict(self):
        return {"risk_score":round(self.risk_score*100,1),"action":self.action,
                "attack_type":self.attack_type,"attack_class_id":self.attack_class_id,
                "confidence":round(self.confidence*100,1),"severity":self.severity,
                "class_probabilities":{k:round(v*100,1) for k,v in self.class_probabilities.items()},
                "from_cache":self.from_cache,"model_version":self.model_version}

def ml_analyze(text,async_feedback=True):
    if not MODEL_LOADED: return MLDecision(0.0,"allow","unknown",severity="none")
    text_str=str(text)
    if len(text_str)<=3: return MLDecision(0.0,"allow","normal",severity="none")
    if len(text_str)<=20 and text_str.isalnum(): return MLDecision(0.0,"allow","normal",severity="none")
    cached=_cache.get(text_str)
    if cached is not None:
        return MLDecision(cached["risk_score"],cached["action"],cached["attack_type"],
                          cached.get("attack_class_id",0),cached.get("confidence",0.0),
                          cached.get("severity","none"),cached.get("class_probabilities",{}),
                          from_cache=True,model_version=cached.get("model_version",_model_version))
    try:
        if _using_v2: risk_score,attack_type,confidence,class_probs=_compute_v2(text_str)
        else: risk_score,attack_type,confidence,class_probs=_compute_v1(text_str)
        action=_make_decision(risk_score)
        severity=SEVERITY_MAP.get(attack_type,"medium")
        if attack_type=="normal" and risk_score>=THRESHOLD_MONITOR: attack_type="attack"; severity="medium"
        attack_class_id=0
        if _label_enc is not None:
            try: attack_class_id=int(list(_label_enc.classes_).index(attack_type))
            except ValueError: pass
        logger.debug(f"[ML] score={risk_score:.2%} action={action} type={attack_type} v={_model_version}")
        payload={"risk_score":risk_score,"action":action,"attack_type":attack_type,
                 "attack_class_id":attack_class_id,"confidence":confidence,
                 "severity":severity,"class_probabilities":class_probs,"model_version":_model_version}
        _cache.set(text_str,payload)
        if action in ("block","monitor") and async_feedback:
            th=hashlib.md5(text_str.encode("utf-8",errors="replace")).hexdigest()
            _executor.submit(_append_feedback,text_str,risk_score,action,attack_type)
            _executor.submit(_log_prediction,th,confidence,attack_type,severity,action,_model_version)
        return MLDecision(risk_score,action,attack_type,attack_class_id,confidence,severity,class_probs,model_version=_model_version)
    except Exception as e:
        logger.error(f"[ML] inference error: {e}")
        return MLDecision(0.0,"allow","error",severity="none")

def ml_detect(text):
    """Backward-compatible: (is_attack: bool, risk_score: float)."""
    d=ml_analyze(text); return d.should_block,d.risk_score

def get_ml_stats():
    return {"model_loaded":MODEL_LOADED,"model_version":_model_version,"using_v2":_using_v2,
            "cache":_cache.stats,"thresholds":{"block":THRESHOLD_BLOCK,"monitor":THRESHOLD_MONITOR},
            "feedback_log":str(FEEDBACK_LOG_PATH)}

_load_or_train()
if MODEL_LOADED and not _using_v2:
    try:
        s=_compute_v1("startup check")[0]
        if not (0.0<=s<=1.0): logger.critical("[ML] out-of-range — retraining..."); _retrain_v1()
    except Exception as e: logger.critical(f"[ML] startup failed: {e} — retraining..."); _retrain_v1()

_retrain_thread=threading.Thread(target=_auto_retrain_loop,daemon=True)
_retrain_thread.start()
logger.info(f"[ML] Ready | version={_model_version} block>={THRESHOLD_BLOCK:.0%} monitor>={THRESHOLD_MONITOR:.0%}")
