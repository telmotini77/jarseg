import os

from cyberseg_engine.audit import ServerAuditor, listening_sockets

PROC_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 2 1 0000000000000000 100 0 0 10 0
   2: 0A01A8C0:0016 3201A8C0:C350 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
"""
PROC_TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0CEA 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5 1 0000000000000000 100 0 0 10 0
"""


def fake_host(tmp_path, sysctl: dict[str, str], sshd: str | None):
    proc = tmp_path / "proc"
    (proc / "net").mkdir(parents=True)
    (proc / "net" / "tcp").write_text(PROC_TCP, encoding="ascii")
    (proc / "net" / "tcp6").write_text(PROC_TCP6, encoding="ascii")
    for key, value in sysctl.items():
        target = proc / "sys" / key
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value + "\n", encoding="ascii")
    ssh = tmp_path / "ssh"
    if sshd is not None:
        (ssh / "sshd_config.d").mkdir(parents=True)
        (ssh / "sshd_config").write_text(sshd, encoding="utf-8")
        (ssh / "sshd_config.d" / "50-cloud.conf").write_text("PasswordAuthentication no\n", encoding="utf-8")
    return str(proc), str(ssh)


def test_listening_sockets_parse_ipv4_and_ipv6(tmp_path):
    proc, _ = fake_host(tmp_path, {}, None)
    assert listening_sockets(proc) == {("tcp", "0.0.0.0", 6379), ("tcp", "127.0.0.1", 5432), ("tcp", "::", 22), ("tcp", "::1", 3306)}


def test_audit_reports_exposed_services_weak_kernel_ssh_and_firewall(tmp_path):
    proc, ssh = fake_host(
        tmp_path,
        {"net/ipv4/tcp_syncookies": "0", "net/ipv4/conf/all/rp_filter": "2", "net/ipv4/conf/all/accept_redirects": "1"},
        "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPasswordAuthentication yes\nMaxAuthTries 10\n",
    )
    auditor = ServerAuditor(proc_root=proc, ssh_dir=ssh, host_label="192.168.1.10", nft_runner=lambda: "table inet cyberseg {\n chain input {\n type filter hook input priority -10; policy accept;\n }\n}")
    findings = {item.key: item for item in auditor.run()}

    assert findings["audit:port:tcp:6379"].severity == "critical"          # Redis on 0.0.0.0
    assert "audit:port:tcp:5432" not in findings and "audit:port:tcp:3306" not in findings  # loopback only
    assert "22/tcp" in findings["audit:ports:inventory"].detail
    assert findings["audit:sysctl:net.ipv4.tcp_syncookies"].severity == "high"
    assert "audit:sysctl:net.ipv4.conf.all.rp_filter" not in findings       # loose mode is fine
    assert "audit:sysctl:net.ipv4.conf.all.accept_redirects" in findings
    assert findings["audit:ssh:permitrootlogin"].severity == "high"
    assert "audit:ssh:passwordauthentication" not in findings               # the Include file wins
    assert "audit:ssh:maxauthtries" in findings
    assert findings["audit:firewall:input-policy"].severity == "medium"
    assert all(item.source == "audit" for item in findings.values())


def test_hardened_host_has_no_kernel_ssh_or_firewall_findings(tmp_path):
    proc, ssh = fake_host(tmp_path, {"net/ipv4/tcp_syncookies": "1", "net/ipv4/conf/all/accept_redirects": "0"}, "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\nMaxAuthTries 3\n")
    os.remove(os.path.join(proc, "net", "tcp"))
    auditor = ServerAuditor(proc_root=proc, ssh_dir=ssh, nft_runner=lambda: "chain input { type filter hook input priority filter; policy drop; }")
    keys = {item.key for item in auditor.run()}
    assert not any(key.startswith(("audit:sysctl", "audit:ssh", "audit:firewall")) for key in keys)
