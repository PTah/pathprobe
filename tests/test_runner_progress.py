from pathprobe.diagnose.runner import run_diagnosis


def test_progress_callback_emits_stages():
    cfg = {
        "peers": {
            "lab": {
                "host": "127.0.0.1",
                "tcp_ports": [1],
                "udp_ports": [],
                "tls": [],
                "dns": {"resolvers": [], "queries": []},
            }
        },
        "timeouts": {
            "dns_sec": 0.2,
            "tcp_sec": 0.2,
            "tls_sec": 0.2,
            "udp_sec": 0.2,
            "mtu_sec": 0.2,
        },
    }
    events: list[tuple[str, str, str]] = []

    def on_progress(peer, stage, event, detail):
        events.append((peer, stage, event))

    report = run_diagnosis(cfg, config_path="memory", on_progress=on_progress)
    assert report.results
    stage_ids = {e[1] for e in events}
    assert "tcp" in stage_ids
    assert "mtu" in stage_ids
    assert any(e[1] == "classify" and e[2] == "done" for e in events)
