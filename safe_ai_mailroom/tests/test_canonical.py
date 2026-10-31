from mailroom import canonical, sha256, proposal_digest

def test_canonical_key_order():
    assert canonical({"b":1,"a":2}) == canonical({"a":2,"b":1})

def test_proposal_digest_sorts_evidence():
    p1 = {"dossierId":"d","callId":"call-id-123456","action":"no_action","target":None,
          "payload":{"reasonCode":"INFORMATIONAL","referenceId":"r"},"evidence":["b","a"]}
    p2 = dict(p1, evidence=["a","b"])
    assert proposal_digest(p1) == proposal_digest(p2)
