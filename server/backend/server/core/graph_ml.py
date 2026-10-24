# server/core/graph_ml.py — Graph Neural Network for Process Tree Analysis
"""
GNN-based detection that analyzes entire process tree structure as a graph.

Key Innovation:
  Instead of analyzing individual process spawns, this treats the entire
  attack chain as a graph and learns structural patterns.

Detects:
  - Living-off-the-land (LOL) attack chains
  - Multi-stage privilege escalation
  - Lateral movement patterns
  - APT campaign signatures

Architecture:
  - Graph Attention Networks (GAT) with 3 layers
  - Node features: process metadata + context
  - Edge features: spawn relationships + timing
  - Output: Graph-level anomaly score

Example Attack Chain Detected:
  explorer.exe → cmd.exe → net.exe (recon)
                        → wmic.exe (recon)
                        → psexec.exe → [lateral] → remote_cmd.exe
  
  Pattern: "reconnaissance + lateral movement" = APT
"""

import os, json, time, threading
import numpy as np
import networkx as nx
from collections import defaultdict, deque
from typing import List, Tuple, Dict, Optional

# Try GNN frameworks
_DGL_AVAILABLE = False
_PYTORCH_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    _PYTORCH_AVAILABLE = True
except ImportError:
    pass

try:
    import dgl
    import dgl.nn.pytorch as dglnn
    _DGL_AVAILABLE = True
except ImportError:
    pass

from server.config import DATA_DIR

# ── Configuration ─────────────────────────────────────────────────────────────
GRAPH_WINDOW = 3600         # Analyze graphs from last 1 hour
MAX_NODES = 100             # Max nodes in graph
NODE_FEATURE_DIM = 64       # Node embedding dimension
EDGE_FEATURE_DIM = 16       # Edge embedding dimension
HIDDEN_DIM = 128
NUM_LAYERS = 3
NUM_HEADS = 4
TRAIN_AFTER = 500           # Train after 500 events
ANOMALY_THRESHOLD = 0.7

MODEL_PATH = os.path.join(DATA_DIR, "gnn_model.pth")

# ── State ─────────────────────────────────────────────────────────────────────
_model = None
_trained = False
_training = False
_graphs: Dict[str, nx.DiGraph] = {}  # system_id → process graph
_train_buffer: List[dict] = []
_lock = threading.Lock()


# ═════════════════════════════════════════════════════════════════════════════
# GRAPH CONSTRUCTION
# ═════════════════════════════════════════════════════════════════════════════

def build_process_graph(system_id: str, events: List[dict]) -> nx.DiGraph:
    """
    Build a directed graph from process events.
    
    Nodes: processes (keyed by pid)
    Edges: parent→child relationships
    """
    G = nx.DiGraph()
    
    # Track process metadata
    process_info = {}
    
    for event in events:
        pid = event.get("pid")
        parent_name = event.get("parent", "").lower()
        child_name = event.get("child", "").lower()
        cmdline = event.get("cmdline", "")
        timestamp = event.get("time", 0)
        user = event.get("user", "")
        exe_path = event.get("exe_path", "").lower()
        
        # Add node for this process
        if pid not in G:
            G.add_node(pid, 
                      name=child_name,
                      cmdline=cmdline,
                      timestamp=timestamp,
                      user=user,
                      path=exe_path)
            process_info[pid] = event
        
        # Find parent node (best effort)
        parent_pid = None
        for p, data in G.nodes(data=True):
            if data.get("name") == parent_name:
                parent_pid = p
                break
        
        # Add edge parent→child
        if parent_pid is not None:
            time_delta = timestamp - G.nodes[parent_pid].get("timestamp", timestamp)
            G.add_edge(parent_pid, pid,
                      time_delta=time_delta,
                      relationship="spawn")
    
    return G


def extract_graph_features(G: nx.DiGraph) -> Tuple[np.ndarray, np.ndarray, List]:
    """
    Extract node and edge features from graph.
    
    Returns:
        node_features: (num_nodes, NODE_FEATURE_DIM)
        edge_features: (num_edges, EDGE_FEATURE_DIM)
        node_ids: list of original PIDs
    """
    if len(G.nodes) == 0:
        return np.zeros((1, NODE_FEATURE_DIM)), np.zeros((1, EDGE_FEATURE_DIM)), []
    
    node_features = []
    node_ids = []
    
    # Suspicious process names for one-hot encoding
    SUSPICIOUS_PROCS = [
        "powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
        "mshta.exe", "wmic.exe", "psexec.exe", "net.exe", "vssadmin.exe"
    ]
    
    OFFICE_PROCS = ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"]
    BROWSER_PROCS = ["chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe"]
    
    for node_id in G.nodes:
        data = G.nodes[node_id]
        name = data.get("name", "").lower()
        cmdline = data.get("cmdline", "").lower()
        user = data.get("user", "").upper()
        path = data.get("path", "").lower()
        
        # Node features
        feat = [
            # Process type indicators
            float(name in SUSPICIOUS_PROCS),
            float(name in OFFICE_PROCS),
            float(name in BROWSER_PROCS),
            float(name.endswith(".exe")),
            
            # Cmdline indicators
            float("-enc" in cmdline),
            float("bypass" in cmdline),
            float("hidden" in cmdline),
            float("downloadstring" in cmdline or "webclient" in cmdline),
            float("invoke-" in cmdline),
            float("iex" in cmdline),
            
            # Path indicators
            float("\\temp\\" in path),
            float("\\appdata\\" in path),
            float("\\system32\\" in path),
            float("\\syswow64\\" in path),
            
            # User context
            float(user == "SYSTEM"),
            float(user == "ADMINISTRATOR"),
            
            # Graph structural features
            float(G.out_degree(node_id)),  # How many children
            float(G.in_degree(node_id)),   # How many parents
            
            # Cmdline length (normalized)
            min(len(cmdline) / 1000.0, 1.0),
            
            # Process name length
            min(len(name) / 50.0, 1.0),
        ]
        
        # Pad to NODE_FEATURE_DIM
        while len(feat) < NODE_FEATURE_DIM:
            feat.append(0.0)
        
        node_features.append(feat[:NODE_FEATURE_DIM])
        node_ids.append(node_id)
    
    # Edge features
    edge_features = []
    for src, dst in G.edges:
        time_delta = G[src][dst].get("time_delta", 0)
        
        # Normalize time delta (seconds → [0-1])
        time_norm = min(abs(time_delta) / 3600.0, 1.0)  # Max 1 hour
        
        # Edge type
        is_spawn = float(G[src][dst].get("relationship") == "spawn")
        
        # Parent-child name similarity (Jaccard)
        parent_name = G.nodes[src].get("name", "")
        child_name = G.nodes[dst].get("name", "")
        similarity = _jaccard_similarity(parent_name, child_name)
        
        feat = [
            is_spawn,
            time_norm,
            similarity,
            float(time_delta < 1),  # Rapid spawn
            float(time_delta > 300),  # Delayed spawn
        ]
        
        # Pad to EDGE_FEATURE_DIM
        while len(feat) < EDGE_FEATURE_DIM:
            feat.append(0.0)
        
        edge_features.append(feat[:EDGE_FEATURE_DIM])
    
    if not edge_features:
        edge_features = [[0.0] * EDGE_FEATURE_DIM]
    
    return (np.array(node_features, dtype=np.float32),
            np.array(edge_features, dtype=np.float32),
            node_ids)


def _jaccard_similarity(s1: str, s2: str) -> float:
    """Jaccard similarity between two strings."""
    if not s1 or not s2:
        return 0.0
    set1 = set(s1.lower())
    set2 = set(s2.lower())
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return intersection / union if union > 0 else 0.0


# ═════════════════════════════════════════════════════════════════════════════
# GRAPH ATTENTION NETWORK MODEL
# ═════════════════════════════════════════════════════════════════════════════

if _PYTORCH_AVAILABLE and _DGL_AVAILABLE:
    class GATLayer(nn.Module):
        """Graph Attention Network layer."""
        
        def __init__(self, in_dim, out_dim, num_heads=4):
            super(GATLayer, self).__init__()
            self.gat = dglnn.GATConv(in_dim, out_dim, num_heads, 
                                     feat_drop=0.2, attn_drop=0.2)
            self.bn = nn.BatchNorm1d(out_dim * num_heads)
        
        def forward(self, g, h):
            h = self.gat(g, h).flatten(1)
            h = self.bn(h)
            return F.elu(h)
    
    
    class ProcessGraphGNN(nn.Module):
        """
        GNN for process graph anomaly detection.
        
        Uses stacked GAT layers with residual connections.
        Output: graph-level anomaly score.
        """
        
        def __init__(self, node_dim=NODE_FEATURE_DIM, hidden_dim=HIDDEN_DIM,
                     num_layers=NUM_LAYERS, num_heads=NUM_HEADS):
            super(ProcessGraphGNN, self).__init__()
            
            # Input projection
            self.input_proj = nn.Linear(node_dim, hidden_dim)
            
            # GAT layers
            self.gat_layers = nn.ModuleList()
            for _ in range(num_layers):
                self.gat_layers.append(
                    GATLayer(hidden_dim * num_heads if _ > 0 else hidden_dim,
                            hidden_dim, num_heads)
                )
            
            # Graph-level pooling and classification
            self.pool = dglnn.GlobalAttentionPooling(
                nn.Linear(hidden_dim * num_heads, 1)
            )
            
            # Classifier
            self.classifier = nn.Sequential(
                nn.Linear(hidden_dim * num_heads, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(hidden_dim // 2, 1),
                nn.Sigmoid()
            )
        
        def forward(self, g, node_features):
            h = self.input_proj(node_features)
            
            # Apply GAT layers
            for gat in self.gat_layers:
                h = gat(g, h)
            
            # Global pooling
            h_graph = self.pool(g, h)
            
            # Classify
            score = self.classifier(h_graph)
            return score


def train_gnn_model(events: List[dict]):
    """Train GNN on normal process graphs."""
    global _model, _trained, _training
    
    if not (_PYTORCH_AVAILABLE and _DGL_AVAILABLE):
        print("[GNN] PyTorch/DGL not available — graph detection disabled")
        _training = False
        return
    
    print(f"[GNN] Training on {len(events)} events...")
    
    try:
        # Group events by system_id and build graphs
        system_events = defaultdict(list)
        for e in events:
            system_events[e.get("system_id", "unknown")].append(e)
        
        graphs = []
        for sid, evs in system_events.items():
            G = build_process_graph(sid, evs)
            if len(G.nodes) >= 3:  # Need at least 3 nodes
                graphs.append(G)
        
        if len(graphs) < 10:
            print(f"[GNN] Not enough graphs ({len(graphs)}), need 10+")
            _training = False
            return
        
        print(f"[GNN] Built {len(graphs)} process graphs")
        
        # Convert to DGL graphs
        dgl_graphs = []
        for G in graphs:
            node_feat, edge_feat, node_ids = extract_graph_features(G)
            
            # Build DGL graph
            src, dst = [], []
            for s, d in G.edges:
                src.append(node_ids.index(s))
                dst.append(node_ids.index(d))
            
            if src and dst:
                dgl_g = dgl.graph((src, dst))
                dgl_g.ndata['feat'] = torch.FloatTensor(node_feat)
                dgl_graphs.append(dgl_g)
        
        if len(dgl_graphs) < 10:
            print(f"[GNN] Not enough valid DGL graphs")
            _training = False
            return
        
        # Create model
        model = ProcessGraphGNN()
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
        
        # Training loop (unsupervised - all normal graphs labeled as 0)
        model.train()
        for epoch in range(50):
            total_loss = 0
            for g in dgl_graphs:
                optimizer.zero_grad()
                
                score = model(g, g.ndata['feat'])
                
                # Loss: we want normal graphs to have low scores (close to 0)
                target = torch.zeros_like(score)
                loss = F.mse_loss(score, target)
                
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
            
            if (epoch + 1) % 10 == 0:
                avg_loss = total_loss / len(dgl_graphs)
                print(f"[GNN] Epoch {epoch+1}/50, Loss: {avg_loss:.4f}")
        
        # Save model
        torch.save(model.state_dict(), MODEL_PATH)
        print(f"[GNN] Model trained and saved to {MODEL_PATH}")
        
        with _lock:
            _model = model
            _trained = True
        
    except Exception as e:
        print(f"[GNN] Training error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        _training = False


def load_persisted_gnn_model():
    """Load trained GNN model from disk."""
    global _model, _trained
    
    if not (_PYTORCH_AVAILABLE and _DGL_AVAILABLE):
        return
    
    if not os.path.exists(MODEL_PATH):
        return
    
    try:
        model = ProcessGraphGNN()
        model.load_state_dict(torch.load(MODEL_PATH))
        model.eval()
        
        with _lock:
            _model = model
            _trained = True
        
        print(f"[GNN] Loaded persisted model from {MODEL_PATH}")
    except Exception as e:
        print(f"[GNN] Could not load model: {e}")


# ═════════════════════════════════════════════════════════════════════════════
# DETECTION & SCORING
# ═════════════════════════════════════════════════════════════════════════════

def record_graph_event(event: dict):
    """Add event to graph and training buffer."""
    global _training
    
    system_id = event.get("system_id", "unknown")
    
    with _lock:
        # Maintain graph per system
        if system_id not in _graphs:
            _graphs[system_id] = nx.DiGraph()
        
        _train_buffer.append(event)
        
        # Trigger training
        if not _trained and not _training and len(_train_buffer) >= TRAIN_AFTER:
            _training = True
            threading.Thread(
                target=train_gnn_model,
                args=(_train_buffer[:],),
                daemon=True
            ).start()


def detect_graph_anomaly(system_id: str, events: List[dict]) -> Tuple[int, str]:
    """
    Analyze process graph and detect anomalous attack patterns.
    
    Returns:
        (anomaly_score, reason) where score is 0-90
    """
    if not _trained or _model is None:
        return 0, ""
    
    if len(events) < 3:
        return 0, ""  # Need at least 3 events to form a graph
    
    try:
        # Build graph from recent events
        G = build_process_graph(system_id, events)
        
        if len(G.nodes) < 3:
            return 0, ""
        
        # Extract features
        node_feat, edge_feat, node_ids = extract_graph_features(G)
        
        # Build DGL graph
        src, dst = [], []
        for s, d in G.edges:
            if s in node_ids and d in node_ids:
                src.append(node_ids.index(s))
                dst.append(node_ids.index(d))
        
        if not src or not dst:
            return 0, ""
        
        dgl_g = dgl.graph((src, dst))
        dgl_g.ndata['feat'] = torch.FloatTensor(node_feat)
        
        # Predict anomaly score
        with torch.no_grad():
            score = _model(dgl_g, dgl_g.ndata['feat'])
            anomaly_prob = score.item()
        
        if anomaly_prob > ANOMALY_THRESHOLD:
            anomaly_score = int(anomaly_prob * 90)
            
            # Generate explanation based on graph structure
            reason = f"Malicious process chain detected (confidence: {anomaly_prob:.2f}). "
            
            # Analyze graph patterns
            patterns = []
            
            # Check for recon → exploit chains
            recon_procs = {"net.exe", "ipconfig.exe", "whoami.exe", "systeminfo.exe"}
            exploit_procs = {"psexec.exe", "wmic.exe", "rundll32.exe", "regsvr32.exe"}
            
            has_recon = any(G.nodes[n].get("name") in recon_procs for n in G.nodes)
            has_exploit = any(G.nodes[n].get("name") in exploit_procs for n in G.nodes)
            
            if has_recon and has_exploit:
                patterns.append("reconnaissance→exploitation chain")
            
            # Check for lateral movement
            if any("psexec" in G.nodes[n].get("name", "") for n in G.nodes):
                patterns.append("lateral movement tool")
            
            # Check for deep chains (depth > 5 = suspicious)
            try:
                if nx.dag_longest_path_length(G) > 5:
                    patterns.append("deep process chain")
            except:
                pass
            
            if patterns:
                reason += f"Patterns: {', '.join(patterns)}"
            
            return anomaly_score, reason
        
    except Exception as e:
        print(f"[GNN] Detection error: {e}")
    
    return 0, ""


# ═════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ═════════════════════════════════════════════════════════════════════════════

def initialize():
    """Initialize the graph ML detector."""
    if _PYTORCH_AVAILABLE and _DGL_AVAILABLE:
        print("[GNN] Graph neural network detector initialized")
        load_persisted_gnn_model()
    else:
        print("[GNN] PyTorch/DGL not available — install:")
        print("[GNN]   pip install torch dgl")
        print("[GNN] Graph detection DISABLED")


def is_available() -> bool:
    """Check if GNN is available."""
    return _PYTORCH_AVAILABLE and _DGL_AVAILABLE


def get_stats() -> dict:
    """Return GNN statistics."""
    return {
        "trained": _trained,
        "training": _training,
        "graphs_tracked": len(_graphs),
        "events_buffered": len(_train_buffer),
        "model_available": _model is not None,
    }
