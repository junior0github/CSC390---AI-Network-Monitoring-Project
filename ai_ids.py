#!/usr/bin/env python3
import json
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from pathlib import Path
import time
from datetime import datetime

# ----- CONFIGURATION -----
SURICATA_LOG = "/var/log/suricata/eve.json"
ZEEK_CONN_LOG = "/home/cpe326/zeek_logs/conn.log"
ZEEK_DNS_LOG = "/home/cpe326/zeek_logs/dns.log"
ALERT_OUTPUT = "/home/cpe326/ai_ids/alerts.csv"
POLL_INTERVAL = 2  # seconds
FEATURE_COLUMNS = [
    'src_ip','dest_ip','src_port','dest_port','proto',
    'duration','orig_bytes','resp_bytes',
    'query_length','num_subdomains',
    'is_nxdomain','answer_count','ttl_avg'
]
# FEATURE_COLUMNS = ['src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto']

# ----- HELPER FUNCTIONS -----
def load_new_lines(file_path, last_pos):
    """Load new lines from the file since last read position."""
    with open(file_path, 'r') as f:
        f.seek(last_pos)
        lines = f.readlines()
        last_pos = f.tell()
    return lines, last_pos

def encode_categoricals(df):
    df_enc = df.copy()

    for col in ['src_ip', 'dest_ip', 'proto']:
        le = LabelEncoder()
        df_enc[col] = le.fit_transform(df_enc[col].astype(str))

    return df_enc

def preprocess_suricata(lines):
    data = []

    for line in lines:
        try:
            event = json.loads(line)
            if 'alert' in event:
                data.append({
                    'src_ip': event.get('src_ip', '0.0.0.0'),
                    'dest_ip': event.get('dest_ip', '0.0.0.0'),
                    'src_port': int(event.get('src_port', 0)),
                    'dest_port': int(event.get('dest_port', 0)),
                    'proto': event.get('proto', 'UNK'),
                    'duration': float(event.get('flow', {}).get('age', 0)),
                    'orig_bytes': int(event.get('flow', {}).get('bytes_toserver', 0)),
                    'resp_bytes': int(event.get('flow', {}).get('bytes_toclient', 0)),

                    # DNS-only features → default 0
                    'query_length': 0,
                    'num_subdomains': 0,
                    'is_nxdomain': 0,
                    'answer_count': 0,
                    'ttl_avg': 0,

                    'timestamp': event.get('timestamp', datetime.now().isoformat())
                })
        except:
            continue

    if not data:
        return pd.DataFrame(), pd.DataFrame()

    df_orig = pd.DataFrame(data)
    df_orig = df_orig.reindex(columns=FEATURE_COLUMNS + ['timestamp'], fill_value=0)
    df_enc = encode_categoricals(df_orig)

    return df_orig, df_enc
# ----- ZEEK PREPROCESSING ----- #
def preprocess_conn(lines):
    data = []

    for line in lines:
        if line.startswith("#") or not line.strip():
            continue

        parts = line.strip().split("\t")

        try:
            data.append({
                'src_ip': parts[2],
                'dest_ip': parts[4],
                'src_port': int(parts[3]),
                'dest_port': int(parts[5]),
                'proto': parts[6],
                'duration': float(parts[8]) if parts[8] != "-" else 0,
                'orig_bytes': int(parts[9]) if parts[9] != "-" else 0,
                'resp_bytes': int(parts[10]) if parts[10] != "-" else 0,

                # DNS-only → default 0
                'query_length': 0,
                'num_subdomains': 0,
                'is_nxdomain': 0,
                'answer_count': 0,
                'ttl_avg': 0,

                'timestamp': parts[0]
            })
        except:
            continue

    if not data:
        return pd.DataFrame(), pd.DataFrame()

    df_orig = pd.DataFrame(data)
    df_orig = df_orig.reindex(columns=FEATURE_COLUMNS + ['timestamp'], fill_value=0)
    df_enc = encode_categoricals(df_orig)

    return df_orig, df_enc

def preprocess_dns(lines):
    data = []

    for line in lines:
        if line.startswith("#") or not line.strip():
            continue

        parts = line.strip().split("\t")

        try:
            query = parts[9]
            answers = parts[21]
            ttls = parts[22]
            rcode_name = parts[15]

            query_length = len(query)
            num_subdomains = query.count('.')

            is_nxdomain = 1 if rcode_name == "NXDOMAIN" else 0

            answer_count = 0 if answers == "-" else len(answers.split(","))
            ttl_avg = 0
            if ttls != "-":
                ttl_values = [float(x) for x in ttls.split(",")]
                ttl_avg = sum(ttl_values) / len(ttl_values)

            data.append({
                'src_ip': parts[2],
                'dest_ip': parts[4],
                'src_port': int(parts[3]),
                'dest_port': int(parts[5]),
                'proto': parts[6],
                'duration': float(parts[8]) if parts[8] != "-" else 0,
                'orig_bytes': 0,
                'resp_bytes': 0,
                'query_length': query_length,
                'num_subdomains': num_subdomains,
                'is_nxdomain': is_nxdomain,
                'answer_count': answer_count,
                'ttl_avg': ttl_avg,
                'timestamp': parts[0]
            })

        except:
            continue

    if not data:
        return pd.DataFrame(), pd.DataFrame()

    df_orig = pd.DataFrame(data)
    df_enc = df_orig.copy()

    for col in ['src_ip', 'dest_ip', 'proto']:
        le = LabelEncoder()
        df_enc[col] = le.fit_transform(df_enc[col].astype(str))

    return df_orig, df_enc

# ----- INIT MODEL -----
model = IsolationForest(contamination=0.01, n_estimators=100, random_state=42)
# Initial dummy training
# dummy = pd.DataFrame({'src_ip':[0],'dest_ip':[0],'src_port':[0],'dest_port':[0],'proto':[0]})
dummy = pd.DataFrame([{
    'src_ip':0,
    'dest_ip':0,
    'src_port':0,
    'dest_port':0,
    'proto':0,
    'duration':0,
    'orig_bytes':0,
    'resp_bytes':0,
    'query_length':0,
    'num_subdomains':0,
    'is_nxdomain':0,
    'answer_count':0,
    'ttl_avg':0
}])

model.fit(dummy[FEATURE_COLUMNS])
model.fit(dummy)

# ----- ENSURE ALERT FILE EXISTS -----
Path(ALERT_OUTPUT).parent.mkdir(parents=True, exist_ok=True)
Path(ALERT_OUTPUT).touch(exist_ok=True)

# ----- MAIN LOOP -----
last_suricata_pos = 0
last_zeek_pos = 0
last_zeek_dns_pos = 0
print("AI IDS running... Monitoring Suricata & Zeek logs in real-time.\n")

while True:

    # ---- SURICATA ----
    suricata_lines, last_suricata_pos = load_new_lines(SURICATA_LOG, last_suricata_pos)
    if suricata_lines:
        df_orig_s, df_enc_s = preprocess_suricata(suricata_lines)

    # ---- ZEEK ----
    zeek_lines, last_zeek_pos = load_new_lines(ZEEK_CONN_LOG, last_zeek_pos)
    if zeek_lines:
        df_orig_z, df_enc_z = preprocess_conn(zeek_lines)

    dns_lines, last_zeek_dns_pos = load_new_lines(ZEEK_DNS_LOG, last_zeek_dns_pos)
    if dns_lines:
        df_orig_dns, df_enc_dns = preprocess_dns(dns_lines)

    # Combine both sources
    frames_orig = []
    frames_enc = []

    if 'df_enc_s' in locals() and not df_enc_s.empty:
        frames_orig.append(df_orig_s)
        frames_enc.append(df_enc_s)

    if 'df_enc_z' in locals() and not df_enc_z.empty:
        frames_orig.append(df_orig_z)
        frames_enc.append(df_enc_z)

    if 'df_enc_dns' in locals() and not df_enc_dns.empty:
        frames_orig.append(df_orig_dns)
        frames_enc.append(df_enc_dns)

    if frames_enc:
        df_orig_all = pd.concat(frames_orig, ignore_index=True)
        df_enc_all = pd.concat(frames_enc, ignore_index=True)

        df_enc_all['anomaly'] = model.predict(df_enc_all[FEATURE_COLUMNS])
        df_orig_all['anomaly'] = df_enc_all['anomaly']

        suspicious = df_orig_all[df_orig_all['anomaly'] == -1]

        if not suspicious.empty:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n[{timestamp}] [ALERT] {len(suspicious)} suspicious events detected!")
            print(suspicious[['timestamp','src_ip','dest_ip','src_port','dest_port','proto','anomaly']])

            suspicious[['timestamp','src_ip','dest_ip','src_port','dest_port','proto','anomaly']].to_csv(
                ALERT_OUTPUT, mode='a', header=False, index=False
            )

        model.fit(df_enc_all[FEATURE_COLUMNS])

    time.sleep(POLL_INTERVAL)
