"""Role tests default variables installation."""

import os
import pytest
import requests
from testinfra.utils.ansible_runner import AnsibleRunner

TESTINFRA_HOSTS = AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_hosts_file(host):
    """
    Tests general host is available with root
    """
    hosts_file = host.file('/etc/hosts')
    assert hosts_file.exists
    assert hosts_file.user == 'root'
    assert hosts_file.group == 'root'


def test_traefik_processes(host):
    """
    Test traefik processes
    """

    assert len(host.process.filter(user='root', comm='traefik')) == 1


def test_traefik_services(host):
    """
    Test traefik services
    """

    if host.system_info.codename == 'jessie':
        output = host.check_output('service {} status'.format("traefik"))
        assert '{} running'.format("traefik") in output
    else:
        service = host.service("traefik")
        assert service.is_running
        assert service.is_enabled


@pytest.mark.parametrize('path,path_type,user,group,mode', [
    ('/etc/traefik', 'directory', 'root', 'root', 0o755),
    ('/etc/traefik.yml', 'file', 'root', 'root', 0o744),
    ('/etc/traefik-dynamic.yml', 'file', 'root', 'root', 0o744)
    ])
def test_traefik_paths(host, path, path_type, user, group, mode):
    """
    Tests Traefik paths
    """
    current_path = host.file(path)

    assert current_path.exists
    if path_type == 'directory':
        assert current_path.is_directory
    elif path_type == 'file':
        assert current_path.is_file
    assert current_path.user == user
    assert current_path.group == group
    assert current_path.mode == mode


@pytest.mark.parametrize('path,path_type,user,group,mode', [
    ('/etc/traefik/logs/access.log', 'file', 'root', 'root', 0o644),
    ('/etc/traefik/logs/traefik.log', 'file', 'root', 'root', 0o644)
    ])
def test_logging_paths(host, path, path_type, user, group, mode):
    """
    Tests Traefik logging paths
    """
    current_path = host.file(path)

    assert current_path.exists
    if path_type == 'directory':
        assert current_path.is_directory
    elif path_type == 'file':
        assert current_path.is_file
    assert current_path.user == user
    assert current_path.group == group
    assert current_path.mode == mode
