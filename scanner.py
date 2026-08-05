# scanner.py — Core scanning engine with deduplication

import docker
import subprocess
import json
import tempfile
import os
from dockerfile_parse import DockerfileParser
from rules import run_all_rules


def connect_docker():
    try:
        client = docker.from_env()
        client.ping()
        return client, None
    except Exception as e:
        return None, str(e)


def get_local_images(client):
    images = []
    for image in client.images.list():
        tag     = image.tags[0] if image.tags else "untagged"
        size_mb = round(image.attrs['Size'] / 1024 / 1024, 2)
        images.append({
            'tag':     tag,
            'id':      image.short_id,
            'size_mb': size_mb
        })
    return images


def get_running_containers(client):
    containers = []
    for c in client.containers.list():
        containers.append({
            'name':   c.name,
            'image':  c.image.tags[0] if c.image.tags else 'unknown',
            'status': c.status,
            'ports':  str(c.ports)
        })
    return containers


def scan_image_with_grype(image_name, deduplicate=True):
    try:
        result = subprocess.run(
            ['grype', image_name, '-o', 'json'],
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode != 0:
            return [], f"Grype error: {result.stderr}"

        data     = json.loads(result.stdout)
        findings = []
        seen     = set()

        for match in data.get('matches', []):
            vuln     = match.get('vulnerability', {})
            severity = vuln.get('severity', 'Unknown')
            cve_id   = vuln.get('id', 'Unknown')
            pkg_name = match.get('artifact', {}).get('name', 'unknown')
            pkg_ver  = match.get('artifact', {}).get('version', '?')

            # Deduplication key
            dedup_key = f"{cve_id}_{pkg_name}_{pkg_ver}"
            if deduplicate and dedup_key in seen:
                continue
            seen.add(dedup_key)

            cvss = 0.0
            for c in vuln.get('cvss', []):
                score = c.get('metrics', {}).get('baseScore', 0.0)
                if score > cvss:
                    cvss = score

            fix_versions = vuln.get('fix', {}).get('versions', [])
            fix_state    = vuln.get('fix', {}).get('state', 'unknown')
            fix_text     = fix_versions[0] if fix_versions else None
            has_fix      = bool(fix_text) and fix_state != 'wont-fix'

            findings.append({
                'rule':        f"CVE: {cve_id}",
                'cve_id':      cve_id,
                'severity':    severity,
                'stride':      map_severity_to_stride(severity),
                'detail': (
                    f"Package: {pkg_name} v{pkg_ver} — "
                    f"{vuln.get('description','No description')[:150]}"
                ),
                'fix':         fix_text if fix_text else 'No fix available yet',
                'has_fix':     has_fix,
                'fix_state':   fix_state,
                'cvss':        cvss,
                'package':     pkg_name,
                'version':     pkg_ver,
                'why': (
                    f"This vulnerability in {pkg_name} enables a "
                    f"{map_severity_to_stride(severity)} attack. "
                    f"CVSS Score: {cvss}"
                ),
                'sdlc_phase':  'Deployment',
                'bad_code':    None,
                'good_code':   None,
            })

        return findings, None

    except subprocess.TimeoutExpired:
        return [], "Grype scan timed out. Try running: grype db update"
    except Exception as e:
        return [], str(e)


def map_severity_to_stride(severity):
    return {
        'Critical':   'Elevation of Privilege',
        'High':       'Tampering',
        'Medium':     'Information Disclosure',
        'Low':        'Repudiation',
        'Negligible': 'Repudiation',
        'Unknown':    'Repudiation'
    }.get(severity, 'Repudiation')


def scan_dockerfile(dockerfile_path):
    try:
        with open(dockerfile_path, 'rb') as f:
            dfp     = DockerfileParser(fileobj=f)
            content = dfp.structure
        findings = run_all_rules(content)
        return findings, None
    except Exception as e:
        return [], str(e)


def calculate_risk_score(findings):
    if not findings:
        return 0
    weights = {
        'Critical':   40,
        'High':       20,
        'Medium':     10,
        'Low':         5,
        'Negligible':  1,
        'Unknown':     2
    }
    score = sum(weights.get(f.get('severity', 'Unknown'), 2) for f in findings)
    return min(score, 100)


def count_by_severity(findings):
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for f in findings:
        sev = f.get('severity', 'Low')
        if sev in counts:
            counts[sev] += 1
        else:
            counts['Low'] += 1
    return counts


def get_fixable_findings(findings):
    return [f for f in findings if f.get('has_fix', False)]


def get_unfixable_findings(findings):
    return [f for f in findings if not f.get('has_fix', False)]


def generate_secure_dockerfile(base_image):
    parts    = base_image.split(':')
    name     = parts[0].split('/')[-1]
    tag      = parts[1] if len(parts) > 1 else 'latest'

    # Pinned stable versions
    pinned = {
        'ubuntu':  'ubuntu:22.04',
        'debian':  'debian:12-slim',
        'python':  'python:3.11.7-slim',
        'node':    'node:18.19.0-alpine',
        'nginx':   'nginx:1.25.3-alpine',
        'mysql':   'mysql:8.0.35',
        'alpine':  'alpine:3.19.0',
        'redis':   'redis:7.2-alpine',
        'postgres':'postgres:16-alpine',
    }

    safe_base   = pinned.get(name, base_image)
    is_alpine   = 'alpine' in safe_base or 'alpine' in base_image

    if is_alpine:
        pkg_install = (
            "RUN apk update && \\\n"
            "    apk add --no-cache curl && \\\n"
            "    rm -rf /var/cache/apk/*"
        )
        user_create = (
            "RUN addgroup -S appgroup && \\\n"
            "    adduser -S appuser -G appgroup && \\\n"
            "    chown -R appuser:appgroup /app"
        )
    else:
        pkg_install = (
            "RUN apt-get update && \\\n"
            "    apt-get install -y --no-install-recommends curl && \\\n"
            "    apt-get clean && \\\n"
            "    rm -rf /var/lib/apt/lists/*"
        )
        user_create = (
            "RUN groupadd -r appgroup && \\\n"
            "    useradd -r -g appgroup appuser && \\\n"
            "    chown -R appuser:appgroup /app"
        )

    healthcheck_cmd = (
        "HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\\n"
        "    CMD wget -qO- http://localhost:8080/health || exit 1"
        if is_alpine else
        "HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\\n"
        "    CMD curl -f http://localhost:8080/health || exit 1"
    )

    dockerfile = f"""# Auto-generated secure Dockerfile
# Base image: {base_image} pinned to {safe_base}
# Generated by Docker Security Scanner
# All 12 security rules applied automatically

FROM {safe_base}

# Rule 12: Metadata labels for audit trail
LABEL maintainer="your-email@example.com"
LABEL version="1.0"
LABEL description="Securely configured container"
LABEL security.scan="docker-security-scanner"

# Rule 11: Set working directory explicitly
WORKDIR /app

# Rule 7 and 9: Install packages securely with cleanup
{pkg_install}

# Rule 4: Copy application files (never use ADD)
COPY . .

# Rule 1: Create non-root user and switch to it
{user_create}

USER appuser

# Rule 3: Expose only necessary port (never expose 22)
EXPOSE 8080

# Rule 6: Health check for container monitoring
{healthcheck_cmd}

# Run application
CMD ["./app"]
"""
    return dockerfile, safe_base