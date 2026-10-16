#!/usr/bin/env python3
"""
classify/classifier.py - Deterministic rule-based intent classifier for
MAVHoney-D46 (v1.3). Operates on protocol-level observables only
(decoded MAVLink message name / NON_MAVLINK_PROBE marker).

Rule (per adaptive-data row; sessions take the highest-priority row):
  * NON_MAVLINK_PROBE            -> SCANNER   (bytes, but no MAVLink frame)
  * name starts with MALFORMED_  -> UNKNOWN   (framed but fails validation)
  * command-type message         -> CONTROL
  * any other valid MAVLink msg  -> RECON     (incl. PING, HEARTBEAT, mission/telemetry)
A session with no adaptive row (no decoded content) is left unlabeled.
"""
import csv, sys, os

CMD = {"COMMAND_LONG","SET_MODE","COMMAND_INT","MISSION_ITEM",
       "MISSION_ITEM_INT","PARAM_SET","SET_ACTUATOR_CONTROL_TARGET"}
PRIORITY = {"CONTROL":4,"RECON":3,"UNKNOWN":2,"SCANNER":1}

def classify_row(msg_name):
    if not msg_name or msg_name == "NON_MAVLINK_PROBE":
        return "SCANNER"
    if msg_name.startswith("MALFORMED"):
        return "UNKNOWN"
    if msg_name in CMD:
        return "CONTROL"
    return "RECON"

def classify_session(msg_names):
    best = "SCANNER"
    for m in msg_names:
        c = classify_row(m)
        if PRIORITY[c] > PRIORITY[best]: best = c
    return best

def _selftest(d):
    mism=tot=0
    for s in ("india","us","static"):
        p=os.path.join(d,s,"adaptive_data.csv")
        if not os.path.exists(p): continue
        for r in csv.DictReader(open(p)):
            tot+=1
            if classify_row(r.get("msg_name","")) != r.get("intent"): mism+=1
    print(f"rows checked: {tot:,}  mismatches: {mism}")
    print("PASS: classifier reproduces released labels exactly" if mism==0 else "FAIL")
    return mism==0

if __name__=="__main__":
    _selftest(sys.argv[1]) if len(sys.argv)>1 else print("usage: classifier.py <dataset>")
