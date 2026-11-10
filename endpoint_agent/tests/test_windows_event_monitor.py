from windows_event_monitor import normalize_windows_event

NS = 'http://schemas.microsoft.com/win/2004/08/events/event'

def event_xml(event_id, record_id, fields='', channel='Security'):
    return f'''<Event xmlns="{NS}"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>{event_id}</EventID><TimeCreated SystemTime="2026-11-09T10:00:00.000Z"/><EventRecordID>{record_id}</EventRecordID><Channel>{channel}</Channel></System><EventData>{fields}</EventData></Event>'''

def test_failed_login_is_real_observation_and_has_stable_id():
    xml = event_xml(4625, 123, '<Data Name="TargetUserName">alice</Data><Data Name="IpAddress">192.0.2.10</Data>')
    first = normalize_windows_event(xml, 'Security', 'LAB-PC')
    second = normalize_windows_event(xml, 'Security', 'LAB-PC')
    assert first['event_type'] == 'LOGIN_FAILURE'
    assert first['source_ip'] == '192.0.2.10'
    assert first['request_id'] == second['request_id']
    assert first['is_suspicious'] is False

def test_audit_log_clear_is_critical_indicator():
    result = normalize_windows_event(event_xml(1102, 44), 'Security', 'LAB-PC')
    assert result['event_type'] == 'WINDOWS_AUDIT_LOG_CLEARED'
    assert result['severity'] == 'CRITICAL'
    assert result['is_suspicious'] is True

def test_routine_service_logon_is_filtered():
    xml = event_xml(4624, 12, '<Data Name="LogonType">5</Data><Data Name="TargetUserName">SYSTEM</Data>')
    assert normalize_windows_event(xml, 'Security', 'LAB-PC') is None

def test_defender_detection_is_high_severity():
    xml = event_xml(1116, 9, '<Data Name="Threat Name">Example.Test</Data>')
    result = normalize_windows_event(xml, 'Microsoft-Windows-Windows Defender/Operational', 'LAB-PC')
    assert result['event_type'] == 'DEFENDER_MALWARE_DETECTED'
    assert result['severity'] == 'HIGH'
    assert 'Example.Test' in result['description']

def test_process_event_does_not_store_command_line():
    xml = event_xml(4688, 99, '<Data Name="NewProcessName">C:\\Windows\\System32\\whoami.exe</Data><Data Name="CommandLine">whoami /all secret</Data>')
    result = normalize_windows_event(xml, 'Security', 'LAB-PC')
    assert 'whoami.exe' in result['description']
    assert 'secret' not in result['description']
