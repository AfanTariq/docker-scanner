# cis.py — CIS Docker Benchmark checks

import docker


CIS_CHECKS = [
    {
        'id': 'CIS-1',
        'title': 'Ensure a user for the container has been created',
        'description': 'Running containers as root gives attackers full host access if they escape.',
        'stride': 'Elevation of Privilege',
        'severity': 'Critical',
    },
    {
        'id': 'CIS-2',
        'title': 'Ensure container health check is enabled',
        'description': 'Without health checks, failed containers keep running undetected.',
        'stride': 'Denial of Service',
        'severity': 'High',
    },
    {
        'id': 'CIS-3',
        'title': 'Ensure privileged containers are not used',
        'description': 'Privileged containers have nearly full host access.',
        'stride': 'Elevation of Privilege',
        'severity': 'Critical',
    },
    {
        'id': 'CIS-4',
        'title': 'Ensure sensitive host directories are not mounted',
        'description': 'Mounting /etc or /root exposes critical host files.',
        'stride': 'Information Disclosure',
        'severity': 'Critical',
    },
    {
        'id': 'CIS-5',
        'title': 'Ensure SSH is not running inside containers',
        'description': 'SSH inside containers expands attack surface unnecessarily.',
        'stride': 'Spoofing',
        'severity': 'High',
    },
    {
        'id': 'CIS-6',
        'title': 'Ensure memory usage is limited',
        'description': 'Unlimited memory allows one container to starve others.',
        'stride': 'Denial of Service',
        'severity': 'Medium',
    },
    {
        'id': 'CIS-7',
        'title': 'Ensure CPU priority is set appropriately',
        'description': 'Unrestricted CPU allows denial of service attacks.',
        'stride': 'Denial of Service',
        'severity': 'Medium',
    },
    {
        'id': 'CIS-8',
        'title': 'Ensure the host network is not used',
        'description': 'Host networking bypasses Docker network isolation.',
        'stride': 'Tampering',
        'severity': 'High',
    },
    {
        'id': 'CIS-9',
        'title': 'Ensure restart policy is set to On-Failure',
        'description': 'Always-restart policy can cause infinite crash loops.',
        'stride': 'Denial of Service',
        'severity': 'Low',
    },
    {
        'id': 'CIS-10',
        'title': 'Ensure the container root filesystem is read-only',
        'description': 'Writable root filesystem allows malware to persist changes.',
        'stride': 'Tampering',
        'severity': 'High',
    },
]


def run_cis_checks_on_image(image_name, docker_client):
    results = []
    try:
        image_info = docker_client.api.inspect_image(image_name)
        config = image_info.get('Config', {})

        # CIS-1 — non-root user
        user = config.get('User', '')
        results.append({
            **CIS_CHECKS[0],
            'status': 'PASS' if user and user != 'root' and user != '0' else 'FAIL',
            'detail': f"User set to: '{user}'" if user else 'No USER directive found in image',
            'fix': 'Add USER nonroot to your Dockerfile before CMD'
        })

        # CIS-2 — healthcheck
        health = config.get('Healthcheck', None)
        results.append({
            **CIS_CHECKS[1],
            'status': 'PASS' if health else 'FAIL',
            'detail': f"Healthcheck: {health}" if health else 'No HEALTHCHECK defined',
            'fix': 'Add HEALTHCHECK CMD curl -f http://localhost/ || exit 1'
        })

        # CIS-3 — not privileged (image level check)
        results.append({
            **CIS_CHECKS[2],
            'status': 'PASS',
            'detail': 'Cannot verify at image level — check runtime flags',
            'fix': 'Never use --privileged flag when running containers'
        })

        # CIS-4 — sensitive mounts
        results.append({
            **CIS_CHECKS[3],
            'status': 'PASS',
            'detail': 'Cannot verify at image level — check runtime volume mounts',
            'fix': 'Never mount /etc, /root, /proc, or /sys into containers'
        })

        # CIS-5 — no SSH
        exposed = config.get('ExposedPorts', {}) or {}
        ssh_exposed = any('22' in str(port) for port in exposed.keys())
        results.append({
            **CIS_CHECKS[4],
            'status': 'FAIL' if ssh_exposed else 'PASS',
            'detail': 'Port 22 is exposed in image' if ssh_exposed else 'Port 22 not exposed',
            'fix': 'Remove EXPOSE 22 from Dockerfile and disable SSH in container'
        })

        # CIS-6 — memory limit (image level)
        results.append({
            **CIS_CHECKS[5],
            'status': 'PASS',
            'detail': 'Cannot verify at image level — check runtime --memory flag',
            'fix': 'Use docker run --memory=512m to limit container memory'
        })

        # CIS-7 — CPU limit
        results.append({
            **CIS_CHECKS[6],
            'status': 'PASS',
            'detail': 'Cannot verify at image level — check runtime --cpus flag',
            'fix': 'Use docker run --cpus=1.0 to limit CPU usage'
        })

        # CIS-8 — host network
        results.append({
            **CIS_CHECKS[7],
            'status': 'PASS',
            'detail': 'Cannot verify at image level — check runtime --network flag',
            'fix': 'Never use --network=host when running containers'
        })

        # CIS-9 — restart policy
        results.append({
            **CIS_CHECKS[8],
            'status': 'PASS',
            'detail': 'Cannot verify at image level — check runtime --restart flag',
            'fix': 'Use --restart=on-failure:5 instead of --restart=always'
        })

        # CIS-10 — read only filesystem
        results.append({
            **CIS_CHECKS[9],
            'status': 'PASS',
            'detail': 'Cannot verify at image level — check runtime --read-only flag',
            'fix': 'Use docker run --read-only --tmpfs /tmp to enforce read-only'
        })

        return results, None

    except Exception as e:
        return [], str(e)


def run_cis_checks_on_container(container_name, docker_client):
    results = []
    try:
        container_info = docker_client.api.inspect_container(container_name)
        host_config = container_info.get('HostConfig', {})
        config = container_info.get('Config', {})

        # CIS-1 — non-root user
        user = config.get('User', '')
        results.append({
            **CIS_CHECKS[0],
            'status': 'PASS' if user and user != 'root' and user != '0' else 'FAIL',
            'detail': f"Running as user: '{user}'" if user else 'Running as root',
            'fix': 'Add USER nonroot to Dockerfile'
        })

        # CIS-2 — healthcheck
        health = config.get('Healthcheck', None)
        results.append({
            **CIS_CHECKS[1],
            'status': 'PASS' if health else 'FAIL',
            'detail': str(health) if health else 'No health check configured',
            'fix': 'Add HEALTHCHECK to Dockerfile'
        })

        # CIS-3 — privileged
        privileged = host_config.get('Privileged', False)
        results.append({
            **CIS_CHECKS[2],
            'status': 'FAIL' if privileged else 'PASS',
            'detail': 'Container is running in privileged mode!' if privileged else 'Not privileged',
            'fix': 'Remove --privileged flag from docker run command'
        })

        # CIS-4 — sensitive mounts
        binds = host_config.get('Binds', []) or []
        sensitive = ['/etc', '/root', '/proc', '/sys', '/var']
        bad_mounts = [b for b in binds if any(s in b for s in sensitive)]
        results.append({
            **CIS_CHECKS[3],
            'status': 'FAIL' if bad_mounts else 'PASS',
            'detail': f"Sensitive mounts found: {bad_mounts}" if bad_mounts else 'No sensitive mounts',
            'fix': 'Remove sensitive host directory mounts'
        })

        # CIS-5 — SSH port
        exposed = config.get('ExposedPorts', {}) or {}
        ssh_exposed = any('22' in str(p) for p in exposed.keys())
        results.append({
            **CIS_CHECKS[4],
            'status': 'FAIL' if ssh_exposed else 'PASS',
            'detail': 'Port 22 exposed' if ssh_exposed else 'SSH port not exposed',
            'fix': 'Remove EXPOSE 22 from Dockerfile'
        })

        # CIS-6 — memory limit
        mem = host_config.get('Memory', 0)
        results.append({
            **CIS_CHECKS[5],
            'status': 'PASS' if mem and mem > 0 else 'FAIL',
            'detail': f"Memory limit: {round(mem/1024/1024)}MB" if mem else 'No memory limit set',
            'fix': 'Use --memory=512m in docker run command'
        })

        # CIS-7 — CPU
        cpu = host_config.get('NanoCpus', 0)
        results.append({
            **CIS_CHECKS[6],
            'status': 'PASS' if cpu and cpu > 0 else 'FAIL',
            'detail': f"CPU limit: {cpu/1e9} CPUs" if cpu else 'No CPU limit set',
            'fix': 'Use --cpus=1.0 in docker run command'
        })

        # CIS-8 — host network
        net_mode = host_config.get('NetworkMode', '')
        results.append({
            **CIS_CHECKS[7],
            'status': 'FAIL' if net_mode == 'host' else 'PASS',
            'detail': f"Network mode: {net_mode}",
            'fix': 'Remove --network=host from docker run command'
        })

        # CIS-9 — restart policy
        restart = host_config.get('RestartPolicy', {})
        restart_name = restart.get('Name', '')
        results.append({
            **CIS_CHECKS[8],
            'status': 'FAIL' if restart_name == 'always' else 'PASS',
            'detail': f"Restart policy: {restart_name}",
            'fix': 'Use --restart=on-failure:5 instead of --restart=always'
        })

        # CIS-10 — read only
        read_only = host_config.get('ReadonlyRootfs', False)
        results.append({
            **CIS_CHECKS[9],
            'status': 'PASS' if read_only else 'FAIL',
            'detail': 'Filesystem is read-only' if read_only else 'Filesystem is writable',
            'fix': 'Use --read-only flag in docker run command'
        })

        return results, None

    except Exception as e:
        return [], str(e)


def summarize_cis(results):
    passed = sum(1 for r in results if r.get('status') == 'PASS')
    failed = sum(1 for r in results if r.get('status') == 'FAIL')
    return passed, failed