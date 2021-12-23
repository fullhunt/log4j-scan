import re
import base64
import pytest
import requests_mock
import importlib
log4j_scan = importlib.import_module("log4j-scan", package='..')

LOCALHOST = 'https://localhost/'
DNS_CUSTOM = 'custom.dns.callback'


def test_args_required(capsys):
    log4j_scan.main([])
    captured = capsys.readouterr()
    assert 'Parameter \'-u\' or \'-l\' is required' in captured.out


def test_default(requests_mock, capsys):
    adapter_dns_register = requests_mock.post('https://interact.sh/register', text='success')
    adapter_dns_save = requests_mock.get('https://interact.sh/poll', json={'data': [], 'extra': None, 'aes_key': 'FAKE'})
    adapter_endpoint = requests_mock.get(LOCALHOST)

    log4j_scan.main(['-u', LOCALHOST])

    captured = capsys.readouterr()

    assert adapter_dns_register.call_count == 1
    assert adapter_endpoint.call_count == 1
    assert adapter_dns_save.call_count == 1
    assert '.interact.sh/' in captured.out
    assert 'Targets does not seem to be vulnerable' in captured.out
    assert 'jndi' in adapter_endpoint.last_request.url
    assert re.match(r'\${jndi:ldap://localhost\..*.interact\.sh/.*}', adapter_endpoint.last_request.headers['User-Agent'])
    assert 'Authorization' not in adapter_endpoint.last_request.headers


def test_custom_dns_callback_host(requests_mock, capsys):
    adapter_endpoint = requests_mock.get(LOCALHOST)
    
    log4j_scan.main(['-u', LOCALHOST, '--custom-dns-callback-host', DNS_CUSTOM ])

    assert adapter_endpoint.call_count == 1
    assert re.match(r'\${jndi:ldap://localhost\.custom.dns.callback/.*}', adapter_endpoint.last_request.headers['User-Agent'])

    captured = capsys.readouterr()
    assert 'Using custom DNS Callback host [custom.dns.callback]' in captured.out 
    assert 'Custom DNS Callback host is provided' in captured.out


def test_custom_tcp_callback_host(requests_mock, capsys):
    adapter_endpoint = requests_mock.get(LOCALHOST)
    
    log4j_scan.main(['-u', LOCALHOST, '--custom-tcp-callback-host', '10.42.42.42:80'])

    assert adapter_endpoint.call_count == 1
    assert re.match(r'\${jndi:ldap://10.42.42.42:80/.*}', adapter_endpoint.last_request.headers['User-Agent'])

    captured = capsys.readouterr()
    assert 'Using custom TCP Callback host [10.42.42.42:80]' in captured.out
    assert 'Custom TCP Callback host is provided' in captured.out


def test_authentication_basic_no_password():
    with pytest.raises(Exception) as ex:
        log4j_scan.main(['-u', LOCALHOST, '--custom-dns-callback-host', DNS_CUSTOM, '--basic-auth-user', 'foo' ])
    assert "'--basic-auth-password' is mandatory when basic authentication user is defined." == str(ex.value)

    
def test_authentication_basic(requests_mock):
    adapter_endpoint_get = requests_mock.get(LOCALHOST)
    adapter_endpoint_post = requests_mock.post(LOCALHOST)
    
    log4j_scan.main(['-u', LOCALHOST, '--custom-dns-callback-host', DNS_CUSTOM, '--basic-auth-user', 'foo', '--basic-auth-password', 'bar', '--run-all-tests'])
    
    assert adapter_endpoint_get.call_count == 1
    assert adapter_endpoint_post.call_count == 2
    
    _basic_auth_encoded = 'Basic Zm9vOmJhcg==' 
    assert _basic_auth_encoded == adapter_endpoint_get.last_request.headers['Authorization'] 
    assert _basic_auth_encoded == adapter_endpoint_post.request_history[0].headers['Authorization']
    assert _basic_auth_encoded == adapter_endpoint_post.request_history[1].headers['Authorization']


def test_authentication_injection_basic_with_user():
    with pytest.raises(Exception) as ex:
        log4j_scan.main(['-u', LOCALHOST, '--custom-dns-callback-host', DNS_CUSTOM, '--authorization-injection', 'basic', '--basic-auth-user', 'foo', '--basic-auth-password', 'bar' ])
    assert "'--authorization-injection' is not compatible when basic authentication is defined." == str(ex.value)


def test_authentication_injection_basic(requests_mock):
    adapter_endpoint = requests_mock.get(LOCALHOST)
    
    log4j_scan.main(['-u', LOCALHOST, '--custom-dns-callback-host', DNS_CUSTOM, '--authorization-injection', 'basic'])
    
    assert adapter_endpoint.call_count == 1
    _basic_auth = 'Basic %s' % base64.b64encode((adapter_endpoint.last_request.headers['User-Agent'] + ':fakepassword').encode('utf-8')).decode()
    assert _basic_auth == adapter_endpoint.last_request.headers['Authorization'] 
    
