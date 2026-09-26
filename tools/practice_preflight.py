"""Read-only local readiness observations; never starts or repairs services."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

if __package__:
    from .check_guided_isolation import port_numbers, render
else:
    from check_guided_isolation import port_numbers, render

ROOT = Path(__file__).resolve().parents[1]


def observations(root, document, run=subprocess.check_output):
    result = {'scope': 'local readiness observations, not a grade or capacity guarantee',
              'checkout_free_bytes': shutil.disk_usage(root).free,
              'docker_memory_bytes': None, 'docker_data_free_bytes': None,
              'docker_available': False, 'compose_version': None, 'ports': [], 'warnings': []}
    try:
        info = json.loads(run(['docker', 'info', '--format', '{{json .}}'], text=True, stderr=subprocess.DEVNULL, timeout=15))
        result['docker_available'] = True
        result['docker_memory_bytes'] = info.get('MemTotal')
        data = Path(info.get('DockerRootDir', '/nonexistent-docker-directory'))
        if data.is_dir():
            result['docker_data_free_bytes'] = shutil.disk_usage(data).free
        result['compose_version'] = run(['docker', 'compose', 'version', '--short'], text=True, stderr=subprocess.DEVNULL, timeout=15).strip()
    except (OSError, ValueError, subprocess.SubprocessError):
        result['warnings'].append('Docker 또는 Compose 접근 실패: 설치·daemon·사용자 권한을 확인하세요.')
    listeners = None
    try:
        lines = run(['ss', '-H', '-lntu'], text=True, stderr=subprocess.DEVNULL, timeout=10).splitlines()
        listeners = {int(line.split()[4].rsplit(':', 1)[-1]) for line in lines
                     if len(line.split()) >= 5 and line.split()[4].rsplit(':', 1)[-1].isdigit()}
    except (OSError, subprocess.SubprocessError):
        result['warnings'].append('listener 목록을 확인하지 못했습니다. 포트가 비었다고 판단하지 않습니다.')
    for port, services in sorted(port_numbers(document).items()):
        state = 'unknown' if listeners is None else 'in_use' if port in listeners else 'not_observed'
        result['ports'].append({'port': port, 'services': services, 'state': state})
        if len(services) > 1:
            result['warnings'].append(f'{port}: Compose 안의 공개 포트가 중복됩니다.')
    result['warnings'].append('in_use는 기존 실습일 수도 있습니다. docker compose ps --all로 소유 서비스를 확인하며 자동 종료하지 않습니다.')
    result['warnings'].append('용량은 현재 관찰값입니다. 여유 공간·메모리 수치만으로 전체 빌드 성공을 보장하지 않습니다.')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--env-file', type=Path)
    parser.add_argument('--file', action='append', help='Repeat in Compose override order')
    args = parser.parse_args()
    root = args.root.resolve()
    env = args.env_file or root / 'llm-security-control-plane/.state/guided-course.env'
    files = args.file or [str(root / 'examples/security-monitoring/compose.guided.yaml')]
    try:
        document = render(files, str(env))
        result = observations(root, document)
    except (OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({'error': '설정 점검 실패: 환경 파일·Compose 경로를 확인하세요. 비밀값과 설정 원문은 출력하지 않습니다.'}, ensure_ascii=False))
        return 3
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['docker_available'] and result['compose_version'] else 3


if __name__ == '__main__':
    raise SystemExit(main())
