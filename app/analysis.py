from collections import defaultdict, Counter
from typing import List, Dict, Tuple
from datetime import datetime, timedelta
import math
import networkx as nx
from .models import LogEvent, GraphNode, GraphEdge, NetworkGraph, AnomalyScore, AnalysisResult, TimelineEntry


def build_graph(events: List[LogEvent]) -> NetworkGraph:
    node_map: Dict[str, GraphNode] = {}
    edge_key_to_edge: Dict[Tuple[str,str], GraphEdge] = {}

    for ev in events:
        # Host nodes
        for ip in [ev.src_ip, ev.dst_ip]:
            if not ip:
                continue
            if ip not in node_map:
                node_map[ip] = GraphNode(id=ip, label=ip, type='host', count=0, last_seen=ev.timestamp)
            node = node_map[ip]
            node.count += 1
            if ev.timestamp > (node.last_seen or ev.timestamp):
                node.last_seen = ev.timestamp
        # Alert node (signature) aggregated
        sig_id = f"sig:{ev.signature}"[:120]
        if sig_id not in node_map:
            node_map[sig_id] = GraphNode(id=sig_id, label=ev.signature[:40], type='alert', count=0, last_seen=ev.timestamp)
        sig_node = node_map[sig_id]
        sig_node.count += 1
        if ev.timestamp > (sig_node.last_seen or ev.timestamp):
            sig_node.last_seen = ev.timestamp
        # Edges host->alert and host->host
        if ev.src_ip:
            k = (ev.src_ip, sig_id)
            if k not in edge_key_to_edge:
                edge_key_to_edge[k] = GraphEdge(source=ev.src_ip, target=sig_id, count=0)
            e = edge_key_to_edge[k]
            e.count += 1
            if ev.signature not in e.alerts:
                e.alerts.append(ev.signature)
            if ev.protocol and ev.protocol not in e.protocols:
                e.protocols.append(ev.protocol)
        if ev.src_ip and ev.dst_ip:
            k2 = (ev.src_ip, ev.dst_ip)
            if k2 not in edge_key_to_edge:
                edge_key_to_edge[k2] = GraphEdge(source=ev.src_ip, target=ev.dst_ip, count=0)
            e2 = edge_key_to_edge[k2]
            e2.count += 1
            if ev.signature not in e2.alerts:
                e2.alerts.append(ev.signature)
            if ev.protocol and ev.protocol not in e2.protocols:
                e2.protocols.append(ev.protocol)

    return NetworkGraph(nodes=list(node_map.values()), edges=list(edge_key_to_edge.values()))


def anomaly_detection(events: List[LogEvent]) -> List[AnomalyScore]:
    # Simple statistical anomaly detection on per-IP alert counts (z-score)
    ip_counts = Counter([e.src_ip for e in events if e.src_ip])
    if not ip_counts:
        return []
    values = list(ip_counts.values())
    mean = sum(values)/len(values)
    var = sum((v-mean)**2 for v in values)/len(values)
    std = math.sqrt(var) if var>0 else 1
    anomalies: List[AnomalyScore] = []
    for ip, cnt in ip_counts.items():
        z = (cnt-mean)/std if std else 0
        if z > 2.5 and cnt > mean + 5:  # heuristic thresholds
            anomalies.append(AnomalyScore(entity_id=ip, score=z, reason=f"High alert volume: {cnt} vs mean {mean:.1f}"))
    anomalies.sort(key=lambda a: a.score, reverse=True)
    return anomalies[:20]


def _attacker_defender_stats(events: List[LogEvent]):
    attacker_counts = Counter()
    defender_counts = Counter()
    for e in events:
        if e.src_ip:
            attacker_counts[e.src_ip] += 1
        if e.dst_ip:
            defender_counts[e.dst_ip] += 1
    top_attacker, top_attacker_count = (None, 0)
    if attacker_counts:
        top_attacker, top_attacker_count = attacker_counts.most_common(1)[0]
    top_defender, top_defender_count = (None, 0)
    if defender_counts:
        top_defender, top_defender_count = defender_counts.most_common(1)[0]
    return top_attacker, top_attacker_count, top_defender, top_defender_count


def _aggregate_timeline(events: List[LogEvent], gap_seconds: int = 60, max_entries: int = 200) -> List[TimelineEntry]:
    """Aggregate sequential events with same (src,dst,signature) if close in time.

    gap_seconds: time gap threshold to start new bucket.
    max_entries: limit for payload size.
    """
    if not events:
        return []
    # Sort by time ascending for reconstruction
    ordered = sorted(events, key=lambda e: e.timestamp)
    buckets: List[TimelineEntry] = []
    current: TimelineEntry | None = None
    gap = timedelta(seconds=gap_seconds)
    for ev in ordered:
        key = (ev.src_ip, ev.dst_ip, ev.signature)
        if current and (current.src_ip, current.dst_ip, current.signature) == key and ev.timestamp - current.end <= gap:
            current.end = ev.timestamp
            current.count += 1
        else:
            # push previous
            if current:
                buckets.append(current)
            current = TimelineEntry(start=ev.timestamp, end=ev.timestamp, src_ip=ev.src_ip, dst_ip=ev.dst_ip, signature=ev.signature, count=1)
            if len(buckets) >= max_entries:
                break
    if current and len(buckets) < max_entries:
        buckets.append(current)
    return buckets


def run_analysis(events: List[LogEvent]) -> AnalysisResult:
    # Take recent subset (last 24h) if timestamps span large range
    if events:
        latest = max(e.timestamp for e in events)
        window_start = latest - timedelta(days=1)
        recent = [e for e in events if e.timestamp >= window_start]
    else:
        recent = []
    graph = build_graph(recent)
    anomalies = anomaly_detection(recent)
    top_attacker, top_attacker_count, top_defender, top_defender_count = _attacker_defender_stats(recent)
    timeline = _aggregate_timeline(recent)
    # Only keep last 100 recent events for API payload
    trimmed_recent = sorted(recent, key=lambda e: e.timestamp, reverse=True)[:100]
    return AnalysisResult(
        graph=graph,
        anomalies=anomalies,
        recent_events=trimmed_recent,
        most_aggressive_attacker=top_attacker,
        most_aggressive_attacker_count=top_attacker_count,
        most_attacked_defender=top_defender,
        most_attacked_defender_count=top_defender_count,
        timeline=timeline,
    )
