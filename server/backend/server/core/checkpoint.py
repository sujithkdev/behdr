"""Versioned JSON recovery state. No pickle or executable serialization."""
import hashlib
import json


def capture():
    from server.core import graph, temporal
    with graph._lock, temporal._lock:
        state = {'version': 1, 'graphs': [[sid, list(g.nodes(data=True)), list(g.edges(data=True))]
                                         for sid, g in graph._graphs.items()],
                 'windows': [[list(key), value] for key, value in temporal._windows.items()]}
        payload = json.dumps(state, allow_nan=False, separators=(',', ':'))
    return payload, hashlib.sha256(payload.encode()).hexdigest()


def restore(payload, checksum):
    from server.core import graph, temporal
    from collections import OrderedDict
    import networkx as nx
    if hashlib.sha256(payload.encode()).hexdigest() != checksum:
        raise RuntimeError('Recovery checkpoint checksum mismatch')
    state = json.loads(payload)
    if state.get('version') != 1:
        raise RuntimeError('Unsupported recovery checkpoint version')
    graphs = OrderedDict()
    for sid, nodes, edges in state['graphs']:
        g = nx.DiGraph()
        g.add_nodes_from(nodes)
        g.add_edges_from(edges)
        graphs[sid] = g
    windows = OrderedDict((tuple(key), value) for key, value in state['windows'])
    with graph._lock, temporal._lock:
        graph._graphs.clear()
        graph._graphs.update(graphs)
        temporal._windows.clear()
        temporal._windows.update(windows)
