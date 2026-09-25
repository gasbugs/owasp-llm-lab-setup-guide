"""Provision only the reserved P20 Viewer; never include learner artifacts."""
import os
import sys
import time

import httpx

LOGIN = 'p20-reader'


def provision(client, admin_password, reader_password):
    if not admin_password or not reader_password or admin_password == reader_password:
        raise ValueError('P20 requires distinct nonempty Grafana credentials')
    admin = ('admin', admin_password)
    dashboard_path = '/api/dashboards/uid/guided-p20'
    deadline = time.monotonic() + 30
    while True:
        dashboard = client.get(dashboard_path + '/permissions', auth=admin)
        if dashboard.status_code != 404:
            dashboard.raise_for_status()
            if any(item.get('role') == 'Viewer' and item.get('permission') == 1
                   for item in dashboard.json()):
                break
        if time.monotonic() >= deadline:
            raise TimeoutError('P20 dashboard Viewer permission readiness')
        time.sleep(.5)
    lookup = client.get('/api/users/lookup', params={'loginOrEmail': LOGIN}, auth=admin)
    if lookup.status_code == 404:
        created = client.post('/api/admin/users', auth=admin, json={
            'name': 'P20 evidence reader', 'email': 'p20-reader@example.com',
            'login': LOGIN, 'password': reader_password, 'OrgId': 1})
        created.raise_for_status()
    else:
        lookup.raise_for_status()
    reader = (LOGIN, reader_password)
    identity = client.get('/api/user', auth=reader)
    identity.raise_for_status()
    user = identity.json()
    if user.get('login') != LOGIN or user.get('isGrafanaAdmin') is not False or user.get('orgId') != 1:
        raise ValueError('P20 reader identity is not the reserved non-admin account')
    memberships = client.get('/api/user/orgs', auth=reader)
    memberships.raise_for_status()
    orgs = memberships.json()
    if len(orgs) != 1 or orgs[0].get('orgId') != 1 or orgs[0].get('role') != 'Viewer':
        raise ValueError('P20 reader must have only the Viewer role in organization 1')
    readable = client.get(dashboard_path, auth=reader)
    readable.raise_for_status()
    return {'login': LOGIN, 'role': 'Viewer', 'orgId': 1}


def main():
    try:
        with httpx.Client(base_url=os.environ['GUIDED_P20_GRAFANA_URL'],
                          timeout=3, follow_redirects=False, trust_env=False) as client:
            deadline = time.monotonic() + 60
            while True:
                try:
                    response = client.get('/api/health')
                    response.raise_for_status()
                    if response.json().get('database') == 'ok':
                        break
                except (httpx.HTTPError, ValueError):
                    pass
                if time.monotonic() >= deadline:
                    raise TimeoutError('Grafana readiness')
                time.sleep(.5)
            provision(client, os.environ['GUIDED_P20_GRAFANA_ADMIN_PASSWORD'],
                      os.environ['GUIDED_P20_GRAFANA_PASSWORD'])
        print('P20 Grafana Viewer ready')
    except (httpx.HTTPError, ValueError, KeyError, TypeError, TimeoutError):
        # Do not print responses, request bodies, credentials or exception tracebacks.
        print('P20 Grafana Viewer preparation failed; check dedicated credentials and account role', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
