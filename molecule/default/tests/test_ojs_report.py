"""OJS registration report installation and output tests."""


def test_ojs_report_collector(host):
    collector = host.file("/usr/local/sbin/ojs-registration-report")
    assert collector.exists
    assert collector.is_file
    assert collector.user == "root"
    assert collector.mode == 0o755


def test_ojs_report_configuration(host):
    config = host.file("/etc/ojs-registration-report.json")
    assert config.exists
    assert config.user == "root"
    assert config.mode == 0o644
    result = host.run("python3 -m json.tool /etc/ojs-registration-report.json")
    assert result.rc == 0


def test_ojs_report_cron(host):
    cron = host.run("crontab -l -u root")
    assert cron.rc == 0
    assert "OJS registration activity report" in cron.stdout
    assert "/usr/local/sbin/ojs-registration-report --config /etc/ojs-registration-report.json" in cron.stdout


def test_ojs_report_output(host):
    report = host.file("/var/lib/ojs-registration-report/latest.md")
    assert report.exists
    assert not host.file("/var/lib/ojs-registration-report/reports/report-2000-01-01.md").exists
    contents = report.content_string
    assert "Registration attempts: **2**" in contents
    assert "Cross-journal registration attempts" in contents
    assert "username=reader" in contents
    assert "secret" not in contents
    assert "upload attempt" in contents
    assert "upload page or asset" in contents
    assert "Traffic overview" in contents
    assert "Busiest hour: **2030-01-02 05:00 AM UTC** (5 requests)" in contents


def test_ojs_traffic_graph(host):
    graph = host.file("/var/lib/ojs-registration-report/traffic/traffic-2030-01-02.png")
    latest = host.file("/var/lib/ojs-registration-report/traffic/latest-traffic.png")
    assert graph.exists
    assert graph.is_file
    assert graph.size > 100
    assert graph.size < 8000
    assert latest.exists
    assert latest.size == graph.size
    png_header = host.run("python3 -c 'print(open(\"/var/lib/ojs-registration-report/traffic/latest-traffic.png\", \"rb\").read(8))'")
    assert png_header.rc == 0
    assert "b'\\x89PNG\\r\\n\\x1a\\n'" in png_header.stdout
