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

Nightly OJS registration activity report
----------------------------------------

The role can install a review-oriented report collector for Traefik JSON
access logs. It is disabled by default. Enable it for the inventory that owns
the production OJS sites:

```yml
ojs_report_enabled: true
ojs_report_sites:
  - name: tuljournals.temple.edu
    hosts:
      - tuljournals.temple.edu
  - name: tupjournals.temple.edu
    hosts:
      - tupjournals.temple.edu
ojs_report_timezone: America/New_York
```

The collector runs at 02:15, reads the preceding 24 hours plus rotated access
logs, and writes reports under `/var/lib/ojs-registration-report/`. It keeps
report files for seven days and keeps registration IP state for seven days so
activity on a later night remains associated with a recent registration. Registrations, activations, and logins
are reported as observed requests, not confirmed success; upload pages and
static upload scripts are distinguished from actual upload attempts.

Optional Teams delivery uses a Microsoft Teams Workflows webhook. Keep the
webhook URL in Ansible Vault as `ojs_report_teams_webhook_url`, then set
`ojs_report_teams_enabled: true`. The role writes the URL to a root-only file
and sends a size-limited summary after each report. Do not commit the webhook
URL to inventory or role files. The Teams summary omits IP addresses, usernames,
request paths, and activation tokens; the detailed report remains on the host.

License
-------

MIT
