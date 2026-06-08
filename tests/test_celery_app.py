from app.tasks.celery_app import celery_app


def test_celery_tasks_are_registered():
    assert "app.tasks.pcap_analysis.analyze_pcap" in celery_app.tasks
    assert "app.tasks.alert_triage.triage_alert" in celery_app.tasks
