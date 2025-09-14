from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class LogEvent(BaseModel):
    timestamp: datetime
    sid: Optional[str] = None
    rev: Optional[str] = None
    gid: Optional[str] = None
    signature: str
    classification: Optional[str] = None
    priority: Optional[int] = None
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None

class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # 'host' | 'alert'
    count: int = 1
    last_seen: Optional[datetime] = None

class GraphEdge(BaseModel):
    source: str
    target: str
    count: int = 1
    protocols: List[str] = []
    alerts: List[str] = []

class NetworkGraph(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]

class AnomalyScore(BaseModel):
    entity_id: str
    score: float
    reason: str

class AnalysisResult(BaseModel):
    graph: NetworkGraph
    anomalies: List[AnomalyScore]
    recent_events: List[LogEvent]
    # Newly added enriched metrics
    most_aggressive_attacker: Optional[str] = None
    most_aggressive_attacker_count: int = 0
    most_attacked_defender: Optional[str] = None
    most_attacked_defender_count: int = 0
    timeline: List['TimelineEntry'] = []  # reconstructed aggregated timeline


class TimelineEntry(BaseModel):
    start: datetime
    end: datetime
    src_ip: Optional[str]
    dst_ip: Optional[str]
    signature: str
    count: int

# Forward reference resolution
AnalysisResult.model_rebuild()
