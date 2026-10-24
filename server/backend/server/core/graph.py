"""Observed process instances. Missing parent creation times remain unresolved."""
import threading
from collections import OrderedDict

import networkx as nx
from server.core.temporal import instance
from server.config import GRAPH_MAX_NODES

_graphs = OrderedDict()
_lock = threading.RLock()


def add_event(event):
    sid = event['system_id']
    with _lock:
        graph = _graphs.setdefault(sid, nx.DiGraph())
        _graphs.move_to_end(sid)
        if len(_graphs) > 1000:
            _graphs.popitem(last=False)
        child = instance(event) or ('event:' + event['event_id'])
        parent = instance(event, parent=True)
        graph.add_node(child, label=event['child'], pid=event['pid'], created=event.get('create_time', 0),
                       parent_identity=parent)
        # Reconcile either arrival order; missing identity never becomes a guessed edge.
        for node, attrs in list(graph.nodes(data=True)):
            candidate = attrs.get('parent_identity')
            if candidate in graph and candidate != node and not nx.has_path(graph, node, candidate):
                graph.add_edge(candidate, node, weight=1)
        while graph.number_of_nodes() > GRAPH_MAX_NODES:
            graph.remove_node(next(iter(graph)))


def rebuild_from_db():
    from server.database.storage import get_all_events_for_graph
    for event in get_all_events_for_graph():
        if event.get('event_id'):
            add_event(event)


def get_chains(system_id, min_len=4):
    with _lock:
        graph = _graphs.get(system_id, nx.DiGraph()).copy()
    chains = []
    for root in [n for n in graph if graph.in_degree(n) == 0]:
        for leaf in [n for n in graph if graph.out_degree(n) == 0]:
            for path in nx.all_simple_paths(graph, root, leaf, cutoff=7):
                if len(path) >= min_len:
                    chains.append([graph.nodes[n]['label'] for n in path])
                if len(chains) >= 100:
                    return chains
    return chains


def to_json(system_id):
    with _lock:
        graph = _graphs.get(system_id, nx.DiGraph())
        return {'nodes': [{'id': n, **data} for n, data in graph.nodes(data=True)],
                'edges': [{'source': a, 'target': b, **data} for a, b, data in graph.edges(data=True)]}
