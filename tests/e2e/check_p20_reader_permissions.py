"""Publisher-only check against the fresh P20 product fixture, not user resources."""
import json
import sys
import time
from pathlib import Path

import httpx


def main():
    with httpx.Client(base_url='http://grafana:3000', auth=('p20-reader', 'publisher-test-reader'),
                      timeout=3, trust_env=False, follow_redirects=False) as client:
        deadline = time.monotonic() + 30
        while True:
            response = client.get('/api/dashboards/uid/guided-p20')
            if response.status_code == 200:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError('P20 dashboard read')
            time.sleep(.25)
        model = response.json()['dashboard']
        write = client.post('/api/dashboards/db', json={'dashboard': model, 'overwrite': True})
        assert write.status_code == 403, write.status_code
        admin = client.get('/api/users')
        assert admin.status_code == 403, admin.status_code
        after = client.get('/api/dashboards/uid/guided-p20')
        after.raise_for_status()
        assert after.json()['dashboard'] == model
        proof = {'dashboard_read': 200, 'dashboard_write': write.status_code,
                 'admin_users_read': admin.status_code, 'dashboard_unchanged': True,
                 'scope': 'actual Grafana 12.1.0 in isolated publisher P20 fixture'}
        Path(sys.argv[1]).write_text(json.dumps(proof, indent=2))


if __name__ == '__main__':
    main()
