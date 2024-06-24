tulibraries.traefik
===================

Ansible role to deploy traefik binary and systemd unit. Fork of kibatic.traefik in order to work with Traefik versions 2.x.x.

Træfɪk is a modern HTTP reverse proxy and load balancer made to deploy microservices with ease. It supports several backends (Docker, Swarm, Kubernetes, Marathon, Mesos, Consul, Etcd, Zookeeper, BoltDB, Rest API, file…) to manage its configuration automatically and dynamically.

Installation
--------------

`$ ansible-galaxy install tulibraries.traefik`

Role Variables
--------------

```yml
traefik_install_dir: /usr/bin
traefik_binary_url: https://github.com/containous/traefik/releases/download/v1.7.5/traefik_linux-amd64
traefik_tmp_path: "/tmp"
traefik_bin_path: "{{ traefik_install_dir }}/traefik"
traefik_config_file: /etc/traefik.toml
# example variables for dynamic configs templates w/traefik version 2.x.x
# traefik_dynamic_configs:
#   - src: traefik-dynamic.toml
#     dest: /etc/traefik-dynamic.toml
# restart traefik on dynamic config changes
# set this to false if using traefiks watch feature on those files
traefik_dynamic_config_restart: true
traefik_template: traefik.toml
traefik_systemd_unit_template: traefik.service
traefik_systemd_unit_dest: /etc/systemd/system/traefik.service
traefik_update: false
traefik_manage_service: true
traefik_service_enabled: true
traefik_service_state: started
traefik_log_rotation: true
traefik_log_dir: /var/log/traefik
traefik_logrotate_postrotate_cmd: 'systemctl kill --signal="USR1" traefik'
```


Configuration
----------------

Create a custom config file `templates/traefik.toml.j2` or `templates/traefik*.yml.j2`.
Override template variable (e.g. in `group_vars/all.yml` )

```yml
traefik_template: templates/traefik.toml
```

Add role to your playbook.

```yml
    - hosts: servers
      roles:
         - { role: kibatic.traefik, tags: traefik }
```

Update Traefik
--------------

You have to change `traefik_binary_url` or update this role. Then run your playbook
with following **extra vars** :

```bash
$ ansible-playbook playbook.yml -t traefik --extra-vars "traefik_update=true"
```

Use same command if you want to downgrade.

License
-------

MIT
