"""Isolated publisher products; no host ports, AWS only with explicit live-baseline opt-in."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "llm-security-control-plane"
sys.path.insert(0, str(ROOT / "tests/e2e/fixtures"))
from p12_suite import CASES, DOCS, ORDER, specifications
from p12_markdown import extract_solution


def run(args, *, timeout=180, cwd=None):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    if result.returncode:
        raise RuntimeError(result.stderr[-4000:] or result.stdout[-4000:] or "publisher command failed")
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    implementation = parser.add_mutually_exclusive_group()
    implementation.add_argument("--starter", action="store_true")
    implementation.add_argument("--alternative", action="store_true")
    implementation.add_argument("--markdown", type=Path, help="Build the exact pipeline.py from the later solution section")
    parser.add_argument("--without-classifier-fault", action="store_true",
                        help="Run the eight valid normal/denied cases; default retains the malformed-classifier negative case")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--deployment", action="store_true", help="Use default Gateway/runner/common verifier/Control Center commands and packaged contract")
    parser.add_argument("--browser-python", type=Path, help="With deployment, execute through the real front proxy and browser")
    live = parser.add_mutually_exclusive_group()
    live.add_argument("--aws-baseline", action="store_true", help="Explicit live AWS normal-only baseline, not task completion")
    live.add_argument("--aws-policy-suite", action="store_true", help="Explicit live AWS run of the server-owned P12 policy contract")
    parser.add_argument("--aws-config-dir", type=Path)
    parser.add_argument("--aws-profile", default="default")
    args = parser.parse_args()
    markdown_source = None
    markdown_digest = None
    if args.markdown:
        try:
            document = args.markdown.read_bytes()
            markdown_source = extract_solution(document.decode('utf-8')).encode('utf-8')
            markdown_digest = hashlib.sha256(document).hexdigest()
        except (OSError, ValueError) as error:
            parser.error(str(error))
    aws = args.aws_baseline or args.aws_policy_suite
    if args.browser_python and (not args.deployment or not args.browser_python.is_file()):
        parser.error("browser-python requires deployment and an existing Python executable")
    if args.deployment and not (args.aws_policy_suite or args.starter):
        parser.error("deployment requires the live policy suite or the no-model-call Starter")
    if aws:
        if args.starter or not args.aws_config_dir or not (args.aws_config_dir / "credentials").is_file():
            parser.error("AWS baseline requires an explicit credential directory and an implemented learner")
        if not args.aws_profile or not args.aws_profile.isascii():
            parser.error("explicit ASCII AWS profile required")
    documents = DOCS
    cases = [case for case in CASES if not args.without_classifier_fault or case[0] != "classifier-error"]
    if args.aws_policy_suite or args.deployment:
        policy = json.loads((CONTROL / "guided-contracts/p12.json").read_text())
        documents = policy["documents"]
        cases = [(spec["input"]["case_id"], spec["input"]["message"], spec["input"]["identity"],
                  spec["status"], len(ORDER) if spec["stop"] is None else ORDER.index(spec["stop"]) + 1,
                  int(spec["stop"] is None or ORDER.index(spec["stop"]) >= ORDER.index("retrieval")))
                 for spec in policy["specifications"]]
        if specifications(cases) != policy["specifications"]:
            raise ValueError("publisher case projection differs from operational contract")
    if args.aws_baseline:
        cases = [case for case in cases if case[0] == "normal"]
    if args.output.exists():
        raise ValueError("choose a new evidence path; previous evidence is preserved")
    if args.browser_python and list(args.output.parent.glob(args.output.stem + '.browser*')):
        raise ValueError("choose a new browser evidence prefix")
    project = "guided-p12-check-" + secrets.token_hex(5)
    network = project + "_default"
    recipes = {"context": "guided-labs/h12-protected-services/Containerfile.context",
               "privacy": "guided-labs/h12-protected-services/Containerfile.privacy",
               "nemo": "guided-labs/h12-protected-services/Containerfile.nemo",
               "gateway": "guided-bedrock-gateway/Containerfile"}
    images, image_ids = {}, {}
    tokens = {service: {role: secrets.token_hex(32)
                       for role in (("control", "verifier") if service == "gateway" else ("control", "service", "verifier"))}
              for service in recipes}
    containers = []
    network_created = False
    browser_network = None
    gateway_origin = "http://gateway:8080" if args.deployment else "http://gateway:8000"

    def required(role):
        directory = CONTROL / f'guided-{role}'
        sources = directory.glob('*.py') if role == 'bedrock-gateway' else [directory / 'server.py']
        return {name: secrets.token_hex(32) for source in sources
                for name in re.findall(r'os.environ\["([A-Z0-9_]+)"\]', source.read_text())}

    with TemporaryDirectory(prefix="p12-publisher-build-") as temporary:
        context = Path(temporary)
        learner = context / "guided-labs/h12-application-pipeline"
        learner.mkdir(parents=True)
        (context / "guided-contracts").mkdir()
        shutil.copy2(CONTROL / "guided-contracts/p12.json", context / "guided-contracts/p12.json")
        for name in ("pipeline.py", "execution.py", "service_client.py", "workflow.py", "run_server.py", "Containerfile"):
            shutil.copy2(CONTROL / "guided-labs/h12-application-pipeline" / name, learner / name)
        if markdown_source is not None:
            (learner / 'pipeline.py').write_bytes(markdown_source)
        elif not args.starter:
            fixture = "p12_pipeline_alternative.py" if args.alternative else "p12_pipeline.py"
            shutil.copy2(ROOT / "tests/e2e/fixtures" / fixture, learner / "pipeline.py")
        build_recipes = {**recipes, "runner": "guided-labs/h12-application-pipeline/Containerfile",
                         "verifier": "guided-evidence-verifier/Containerfile"}
        if args.deployment:
            build_recipes['control'] = 'guided-control-center/Containerfile'
        if args.browser_python:
            build_recipes['proxy'] = 'guided-front-proxy/Containerfile'
        for service, recipe in build_recipes.items():
            image = "localhost/" + project + "-" + service + ":test"
            run(["docker", "build", "-f", recipe, "-t", image, "."], cwd=context if service == "runner" else CONTROL)
            images[service] = image
            image_ids[service] = run(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
            print("built " + service, file=sys.stderr, flush=True)
        try:
            run(["docker", "network", "create", *([] if aws else ["--internal"]),
                 "--label", "p12.publisher=" + project, network])
            network_created = True

            def command(service, environment):
                name = project + "-" + service
                probe = subprocess.run(["docker", "container", "inspect", name], capture_output=True)
                if probe.returncode == 0:
                    raise RuntimeError("generated container name already exists")
                containers.append(name)
                uid, gid = (os.getuid(), os.getgid()) if service == "gateway" and aws else (65532, 65532)
                result = ["docker", "run", "--name", name, "--network", network, "--network-alias", service,
                          "--label", "p12.publisher=" + project, "--read-only", "--cap-drop", "ALL",
                          "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,size=128m",
                          "--tmpfs", f"/state:rw,nosuid,size=32m,uid={uid},gid={gid}"]
                if service == "gateway" and aws:
                    result += ["--user", f"{uid}:{gid}"]
                for key, value in environment.items():
                    result += ["-e", key + "=" + value]
                return result

            for service in recipes:
                environment = {f"GUIDED_P12_{service.upper()}_{role.upper()}_TOKEN": token for role, token in tokens[service].items()}
                if service == "nemo":
                    environment["GUIDED_P12_GATEWAY_URL"] = gateway_origin
                if service == "gateway" and args.deployment:
                    environment = {**required('bedrock-gateway'), **environment,
                                   'GUIDED_PROVIDER_MODE': 'aws',
                                   'GUIDED_P12_GATEWAY_DATABASE': '/state/p12-gateway.sqlite3'}
                if service == "gateway" and aws:
                    environment.update(AWS_PROFILE=args.aws_profile, AWS_REGION="us-east-1",
                        AWS_SHARED_CREDENTIALS_FILE="/tmp/.aws/credentials", AWS_CONFIG_FILE="/tmp/.aws/config",
                        AWS_EC2_METADATA_DISABLED="true")
                base = command(service, environment) + ["-d"]
                if service == "gateway":
                    if aws:
                        base += ["-v", str(args.aws_config_dir.resolve()) + ":/tmp/.aws:ro"]
                    if args.deployment:
                        base += [images[service]]
                    else:
                        module = "p12_live_gateway" if aws else "p12_sdk_fixture"
                        base += ["-v", str(ROOT / f"tests/e2e/fixtures/{module}.py") + f":/app/{module}.py:ro",
                                 "--entrypoint", "uvicorn", images[service], module + ":app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "warning"]
                else:
                    base += [images[service]]
                run(base)
            runner_tokens = {role: secrets.token_hex(32) for role in ("control", "verifier")}
            verifier_control = secrets.token_hex(32)
            if args.deployment:
                origins = {f'GUIDED_P12_{name.upper()}_URL': f'http://{name}:8000' for name in recipes}
                origins['GUIDED_P12_GATEWAY_URL'] = gateway_origin
                runner_env = {**origins, 'GUIDED_CONTROL_LAB12_TOKEN': runner_tokens['control'],
                              'GUIDED_VERIFIER_LAB12_TOKEN': runner_tokens['verifier']}
                runner_env.update({f'GUIDED_P12_{name.upper()}_{role.upper()}_TOKEN': value
                                  for name, roles in tokens.items() for role, value in roles.items() if role != 'verifier'})
                verifier_env = {**required('evidence-verifier'), **origins,
                                'GUIDED_CONTROL_VERIFIER_TOKEN': verifier_control,
                                'GUIDED_VERIFIER_LAB12_TOKEN': runner_tokens['verifier'],
                                'GUIDED_LAB12_URL': 'http://runner:8000'}
                verifier_env.update({f'GUIDED_P12_{name.upper()}_VERIFIER_TOKEN': roles['verifier'] for name, roles in tokens.items()})
                control_env = {**required('control-center'), 'GUIDED_CONTROL_LAB12_TOKEN': runner_tokens['control'],
                               'GUIDED_CONTROL_VERIFIER_TOKEN': verifier_control, 'GUIDED_LAB12_URL': 'http://runner:8000',
                               'GUIDED_VERIFIER_URL': 'http://verifier:8000', 'GUIDED_ALLOWED_HOSTS': 'control:8000',
                               'GUIDED_ALLOWED_ORIGINS': 'http://control:8000'}
                if args.browser_python:
                    with socket.socket() as listener:
                        listener.bind(('127.0.0.1', 0))
                        port = listener.getsockname()[1]
                    origin = f'http://127.0.0.1:{port}'
                    control_env['GUIDED_ALLOWED_HOSTS'] += f',127.0.0.1:{port}'
                    control_env['GUIDED_ALLOWED_ORIGINS'] += ',' + origin
                for name, values in (('runner', runner_env), ('verifier', verifier_env), ('control', control_env)):
                    extra = ['--network-alias', 'guided-control-center'] if name == 'control' else []
                    run(command(name, values) + ['-d', *extra, images[name]])
                driver_env = {'P12_RUNNER_VERIFIER': runner_tokens['verifier'], 'P12_VERIFIER_CONTROL': verifier_control,
                              'P12_CHECK_STARTER': '1' if args.starter else '0'}
                if args.browser_python:
                    browser_network = project + '_browser'
                    run(['docker', 'network', 'create', '--label', 'p12.publisher=' + project, browser_network])
                    run(command('proxy', {}) + ['-d', '--network', browser_network,
                        '-p', f'127.0.0.1:{port}:18097', '--tmpfs',
                        '/var/cache/nginx:rw,noexec,nosuid,size=16m,uid=101,gid=101,mode=0700', images['proxy']])
                    run(command('probe', {**driver_env, 'P12_READY_ONLY': '1'}) + ['-v',
                        str(ROOT / 'tests/e2e/run_guided_p12_deployment.py') + ':/check.py:ro',
                        '--entrypoint', 'python', images['runner'], '/check.py'])
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    browser_output = args.output.with_suffix('.browser.json')
                    run([str(args.browser_python.absolute()), str(ROOT / 'tests/browser/check_guided_p12_live.py'),
                         origin, str(browser_output), '--source-digest', hashlib.sha256((learner / 'pipeline.py').read_bytes()).hexdigest(),
                         *(['--incomplete'] if args.starter else [])], timeout=1100)
                    browser_evidence = json.loads(browser_output.read_text())
                    driver_env['P12_EXISTING_ENVELOPE'] = json.dumps(browser_evidence['response'])
                raw = run(command('driver', driver_env) + ['-v', str(ROOT / 'tests/e2e/run_guided_p12_deployment.py') + ':/check.py:ro',
                          '--entrypoint', 'python', images['runner'], '/check.py'], timeout=1100)
                evidence = json.loads(raw.splitlines()[-1])
                evidence.update(project=project, image_ids=image_ids, alternative=args.alternative,
                                aws_policy_suite=args.aws_policy_suite, deployment=True,
                                gateway_entrypoint='packaged server:app on port 8080',
                                publisher_artifacts={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                    for path in (Path(__file__).resolve(), ROOT / 'tests/e2e/run_guided_p12_deployment.py',
                                                 CONTROL / 'guided-contracts/p12.json', CONTROL / 'guided-evidence-verifier/p12_deployment.py',
                                                 CONTROL / 'guided-control-center/server.py', CONTROL / 'guided-evidence-verifier/server.py',
                                                 CONTROL / 'guided-bedrock-gateway/server.py', CONTROL / 'guided-bedrock-gateway/p12_gateway.py',
                                                 CONTROL / 'guided-bedrock-gateway/Containerfile')})
                if args.browser_python:
                    evidence['browser'] = browser_evidence
                    evidence['publisher_artifacts']['tests/browser/check_guided_p12_live.py'] = hashlib.sha256(
                        (ROOT / 'tests/browser/check_guided_p12_live.py').read_bytes()).hexdigest()
                if markdown_source is not None:
                    evidence['markdown'] = {'document_sha256': markdown_digest,
                                            'pipeline_sha256': hashlib.sha256(markdown_source).hexdigest()}
                    evidence['publisher_artifacts']['tests/e2e/p12_markdown.py'] = hashlib.sha256(
                        (ROOT / 'tests/e2e/p12_markdown.py').read_bytes()).hexdigest()
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n')
                print(json.dumps({'project': project, 'cases': evidence['cases'], 'deployment': True,
                                  'task_completed': evidence['grade']['task_completed'], 'evidence': str(args.output)}))
                return
            config = {"control_token": verifier_control, "origin": "http://runner:8000", "token": runner_tokens["verifier"],
                      "origins": {name: f"http://{name}:8000" for name in recipes},
                      "tokens": {name: roles["verifier"] for name, roles in tokens.items()},
                      "specifications": specifications(cases), "documents": documents,
                      "scaffold_files": {name: hashlib.sha256((learner / name).read_bytes()).hexdigest()
                          for name in ("Containerfile", "execution.py", "service_client.py", "workflow.py", "run_server.py")}}
            run(command("verifier", {"P12_VERIFIER_CONFIG": json.dumps(config)}) + ["-d",
                "-v", str(ROOT / "tests/e2e/fixtures/p12_verifier_fixture.py") + ":/app/p12_verifier_fixture.py:ro",
                "--entrypoint", "uvicorn", images["verifier"], "p12_verifier_fixture:app", "--host", "0.0.0.0",
                "--port", "8000", "--log-level", "warning"])
            environment = {f"GUIDED_P12_{service.upper()}_{role.upper()}_TOKEN": token
                           for service, roles in tokens.items() for role, token in roles.items()}
            environment.update({"P12_RUNNER_" + role.upper(): token for role, token in runner_tokens.items()})
            environment["P12_VERIFIER_CONTROL"] = verifier_control
            environment["P12_CHECK_STARTER"] = "1" if args.starter else "0"
            environment["P12_WITHOUT_CLASSIFIER_FAULT"] = "1" if args.without_classifier_fault else "0"
            environment["P12_AWS_BASELINE"] = "1" if args.aws_baseline else "0"
            environment["P12_AWS_POLICY_SUITE"] = "1" if args.aws_policy_suite else "0"
            environment["P12_PUBLISHER_CASES"] = json.dumps(cases)
            environment["P12_PUBLISHER_DOCUMENTS"] = json.dumps(documents)
            raw = run(command("runner", environment) + ["-v", str(ROOT / "tests/e2e/run_guided_p12_products.py") + ":/check.py:ro",
                      "-v", str(ROOT / "tests/e2e/fixtures/p12_suite.py") + ":/checks/p12_suite.py:ro",
                      "-v", str(CONTROL / "guided-evidence-verifier/p12_results.py") + ":/checks/p12_results.py:ro",
                      "-v", str(CONTROL / "guided-evidence-verifier/p12_binding.py") + ":/checks/p12_binding.py:ro",
                      "-v", str(CONTROL / "guided-evidence-verifier/p12_grading.py") + ":/checks/p12_grading.py:ro",
                      "-v", str(CONTROL / "guided-evidence-verifier/p12_verification.py") + ":/checks/p12_verification.py:ro",
                      "--entrypoint", "python", images["runner"], "/check.py"], timeout=600)
            evidence = json.loads(raw.splitlines()[-1])
            evidence.update(project=project, image_ids=image_ids, alternative=args.alternative,
                            aws_baseline=args.aws_baseline, aws_policy_suite=args.aws_policy_suite,
                            publisher_artifacts={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in (Path(__file__).resolve(), ROOT / "tests/e2e/run_guided_p12_products.py",
                                             CONTROL / "guided-evidence-verifier/p12_results.py",
                                             CONTROL / "guided-evidence-verifier/p12_binding.py",
                                             CONTROL / "guided-evidence-verifier/p12_grading.py",
                                             CONTROL / "guided-evidence-verifier/p12_api.py",
                                             CONTROL / "guided-evidence-verifier/p12_verification.py",
                                             ROOT / "tests/e2e/fixtures/p12_suite.py",
                                             ROOT / "tests/e2e/fixtures/p12_verifier_fixture.py",
                                             ROOT / "tests/e2e/fixtures/p12_live_gateway.py",
                                             CONTROL / "guided-contracts/p12.json",
                                             ROOT / "tests/e2e/fixtures/p12_sdk_fixture.py")})
            if markdown_source is not None:
                evidence['markdown'] = {'document_sha256': markdown_digest,
                                        'pipeline_sha256': hashlib.sha256(markdown_source).hexdigest()}
                evidence['publisher_artifacts']['tests/e2e/p12_markdown.py'] = hashlib.sha256(
                    (ROOT / 'tests/e2e/p12_markdown.py').read_bytes()).hexdigest()
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
            print(json.dumps({"project": project, "starter": args.starter, "cases": evidence["cases"],
                              "evidence": str(args.output)}))
        finally:
            for name in reversed(containers):
                probe = subprocess.run(["docker", "inspect", "--format", '{{index .Config.Labels "p12.publisher"}}', name], capture_output=True, text=True)
                if probe.returncode == 0:
                    if probe.stdout.strip() != project:
                        raise RuntimeError("container ownership mismatch; refusing cleanup")
                    run(["docker", "rm", "-f", name])
            if browser_network:
                run(['docker', 'network', 'rm', browser_network])
            if network_created:
                run(["docker", "network", "rm", network])


if __name__ == "__main__":
    main()
