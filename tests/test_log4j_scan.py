import re
import importlib  
log4j_scan = importlib.import_module("log4j-scan", package='..')


def test_args_required(capsys):
    log4j_scan.main([])
    captured = capsys.readouterr()
    assert 'Parameter \'-u\' or \'-l\' is required' in captured.out


def test_default(requests_mock, capsys):
    adapter_dns_register = requests_mock.post('https://interact.sh/register', text='success')
    adapter_dns_save = requests_mock.get('https://interact.sh/poll', json={'data': [], 'extra': None, 'aes_key': 'FAKE'})
    adapter_endpoint = requests_mock.get('https://localhost/')

    log4j_scan.main(['-u', 'https://localhost/'])

    captured = capsys.readouterr()

    assert adapter_dns_register.call_count == 1
    assert adapter_endpoint.call_count == 1
    assert adapter_dns_save.call_count == 1
    assert '.interact.sh/' in captured.out
    assert 'Targets does not seem to be vulnerable' in captured.out
    assert 'jndi' in adapter_endpoint.last_request.url
    assert re.match(r'\${jndi:ldap://localhost\..*.interact\.sh/.*}', adapter_endpoint.last_request.headers['User-Agent'])
    
