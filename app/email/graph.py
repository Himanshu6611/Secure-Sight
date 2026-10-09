"""Traceable graph without private bodies or addresses."""
def build_graph(result):
    identity = result["message"]["email_id"]
    nodes = [{"id": identity, "type": "EMAIL"}]
    edges = []
    for field in ("from", "sender", "reply-to", "return-path"):
        for i, box in enumerate(result["message"]["headers"]["identities"][field]):
            node_id = field + ":" + str(i)
            nodes.append({"id": node_id, "type": field.upper().replace("-", "_"), "mailbox_sha256": box["mailbox_sha256"]})
            edges.append({"source": identity, "target": node_id, "relationship": "HAS_" + field.upper()})
            if box["domain"]:
                domain_id = "domain:" + box["domain"]
                if not any(n["id"] == domain_id for n in nodes):
                    nodes.append({"id": domain_id, "type": "DOMAIN", "hostname": box["domain"]})
                edges.append({"source": node_id, "target": domain_id, "relationship": "USES_DOMAIN", "authenticated": False})
    for attachment in result["attachments"]:
        node_id = "attachment:" + attachment["sha256"]
        if not any(n["id"] == node_id for n in nodes):
            nodes.append({"id": node_id, "type": "ATTACHMENT", "sha256": attachment["sha256"]})
        edges.append({"source": identity, "target": node_id, "relationship": "ATTACHED"})
    graphs = [("media:" + str(i), item["graph"]) for i, item in enumerate(result["media"])]
    graphs.extend(("website:" + str(i), row["analysis"].get("brand_intelligence", {}).get("evidence_graph", {})) for i, row in enumerate(result["urls"]))
    for prefix, graph in graphs:
        for node in graph.get("nodes", [])[:128]:
            nodes.append({**node, "id": prefix + ":" + node["id"]})
            edges.append({"source": identity, "target": prefix + ":" + node["id"], "relationship": "CORRELATED_EVIDENCE"})
        for edge in graph.get("edges", [])[:256]:
            edges.append({**edge, "source": prefix + ":" + edge["source"], "target": prefix + ":" + edge["target"]})
    for i, row in enumerate(result["urls"]):
        nodes.append({"id": f"url:{i}", "type": "URL", "value": row["url"], "discovery_sources": row["sources"]})
        edges.append({"source": identity, "target": f"url:{i}", "relationship": "CONTAINS_DESTINATION"})
    return {"version": "11.0", "nodes": nodes[:512], "edges": edges[:1024]}
