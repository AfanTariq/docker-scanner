## Docker Security Scanner

An AI-powered Docker container security platform that combines CVE vulnerability scanning, Dockerfile static analysis, STRIDE threat model mapping, CIS Docker Benchmark compliance, live container monitoring, and a locally running AI assistant in a single web-based interface. Built with Python and Streamlit, runs entirely on your local machine with no cloud dependency.

---

### What Makes This Different

Most security scanners output a raw list of CVE IDs with severity scores. They tell you something is vulnerable but not what type of attack it enables or which issue to fix first. This tool solves both problems by mapping every finding to a STRIDE threat category and providing an AI assistant that answers security questions grounded in your actual scan data.

| Feature |Trivy  |Grype  |Snyk  |This Tool  |
| --- | --- | --- | --- | --- |
| CVE scanning | Yes | Yes | Yes | Yes |
| Dockerfile rules | Yes | No | Yes | Yes |
| STRIDE mapping | No | No | No | Yes |
| AI chat assistant | No | No | Limited | Yes |
| Image comparison | No | No | No | Yes |
| Risk trend analysis | No | No | No | Yes |
| Secure Dockerfile generator | No | No | No | Yes |
| CIS benchmark | No | No | Partial | Yes |
| Free and open source | Yes | Yes | No | Yes |
| Runs fully offline | Yes | Yes | No | Yes |

---

### Features

#### Tab 1 — CVE Vulnerability Scanner

Scans every package inside a Docker image against 200,000+ known CVEs using the Grype engine. Results are deduplicated so the same CVE affecting multiple packages is shown once per package. Every finding is mapped to a STRIDE threat category and given a fix availability status. Filter by STRIDE category, severity level, or fix availability. A weighted risk score is calculated across all findings.

#### Tab 2 — Dockerfile Static Analysis

Checks your Dockerfile against 12 security rules using static analysis. No code is executed. The file is parsed line by line and each instruction is checked against security patterns. Every violation shows the bad code, the secure alternative, why the issue matters, which STRIDE category it maps to, and which phase of the SDLC it should be caught in. Supports paste or file upload.

#### Tab 3 — CIS Docker Benchmark

Runs 10 official Center for Internet Security Docker Benchmark checks against images or running containers. Shows pass/fail status with a percentage score, description of each check, and fix instructions. Each check is mapped to a STRIDE category.

#### Tab 4 — Image Comparison

Scans two Docker images simultaneously and compares their security posture side by side. Shows labeled severity breakdowns for each image, a detailed verdict on which image wins on Critical findings, High findings, and total findings, and three lists showing CVEs unique to each image and CVEs shared between both.

#### Tab 5 — Secure Dockerfile Generator

Generates a security-hardened Dockerfile template from any base image. Automatically pins unpinned tags to specific stable versions. Applies all 12 security rules including non-root user, HEALTHCHECK, WORKDIR, LABEL, COPY instead of ADD, package cleanup, and no SSH exposure. Detects whether the base image is Alpine or Debian-based and uses the correct package manager commands. The generated file can be downloaded and then scanned in Tab 2 to verify it passes all rules.

#### Tab 6 — AI Chat Assistant

Ask questions about your scan results in plain language. The AI runs locally using Ollama with no internet connection required and no data sent externally. Scan findings are passed as context so all answers are grounded in your actual scan data. Includes quick question buttons for common queries and maintains conversation history within the session.

#### Tab 7 — AI Executive Summary

Generates a plain-language paragraph summarizing the overall security posture of a scanned image, written for non-technical stakeholders. Also generates a ranked top 5 priority fix list where the AI reasons about severity, exploitability, and fix availability together.

#### Tab 8 — Live Container Monitoring

Shows real-time CPU, memory, network, and disk stats for running containers using the Docker stats API. Updates on manual refresh or on a 4-second auto-refresh cycle. Displays scrolling line charts of CPU and memory over time and network traffic over time.

#### Tab 9 — Risk Trend Analysis

Reads the local scan history and generates two charts. A line chart shows risk score over time across all scans with color-coded risk zone bands. A stacked bar chart shows severity breakdown per scan. Trend stats show whether your security posture is improving or worsening since the first scan.

#### Tab 10 — Scan History

Every scan is saved automatically after completion. Stores up to 20 scans with timestamps, risk scores, severity counts, scan type, and the top findings. Use this to track remediation progress over time.

#### Tab 11 — PDF Report

Generates a professional downloadable PDF report from any completed scan. Contains scan summary, STRIDE threat category breakdown table, full findings table sorted by severity, and fix version per CVE where available.

---

### STRIDE Threat Model Mapping

Every finding is tagged with one of the six STRIDE categories:

| Category |Description  |Docker Example  |
| --- | --- | --- |
| Spoofing | Identity impersonation attacks | SSH port 22 exposed |
| Tampering | Data or code modification | Unpinned image tags |
| Repudiation | Audit trail and logging issues | No LABEL metadata |
| Information Disclosure | Unauthorized data exposure | Hardcoded secrets in ENV |
| Denial of Service | Availability disruption | No HEALTHCHECK defined |
| Elevation of Privilege | Unauthorized access escalation | Running as root user |

---

### The 12 Dockerfile Security Rules

| Rule |Severity  |STRIDE  |What It Checks  |
| --- | --- | --- | --- |
| Rule 1 | Critical | Elevation of Privilege | No USER directive — runs as root |
| Rule 2 | Critical | Information Disclosure | Hardcoded secrets in ENV |
| Rule 3 | Critical | Spoofing | SSH port 22 exposed |
| Rule 4 | Critical | Tampering | ADD used instead of COPY |
| Rule 5 | High | Tampering | Unpinned or latest image tag |
| Rule 6 | High | Denial of Service | No HEALTHCHECK defined |
| Rule 7 | High | Elevation of Privilege | apt-get without no-install-recommends |
| Rule 8 | High | Tampering | curl or wget piped to bash |
| Rule 9 | High | Tampering | apt-get install without apt-get update |
| Rule 10 | Medium | Information Disclosure | Sensitive file copied into image |
| Rule 11 | Low | Tampering | No WORKDIR set |
| Rule 12 | Low | Repudiation | No LABEL metadata |

---

### Risk Scoring Formula

The risk score combines severity weights across all findings and caps at 100.

For CVE scans:

```
Critical  = 40 points each
High      = 20 points each
Medium    = 10 points each
Low       =  5 points each
Cap       = 100
```

For Dockerfile analysis a different formula is used since the maximum possible findings is bounded by the 12 rules:

```
Critical  = 25 points each
High      = 15 points each
Medium    =  8 points each
Low       =  3 points each
Cap       = 100
```

The scoring is STRIDE-weighted. Critical findings that enable Elevation of Privilege attacks carry the most weight because privilege escalation represents the highest impact threat category in container environments.

---

### Requirements

- Windows 10 or 11, Linux, or macOS
- Docker Desktop installed and running
- Python 3.11 or higher
- Grype vulnerability scanner
- Ollama with llama3.2 model (for AI features)
- Minimum 8GB RAM recommended
- Minimum 10GB free disk space

---

### Installation

#### Step 1 — Install Docker Desktop

Download from [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop) and install. Make sure it is running before using the tool. You will see the whale icon in your taskbar when it is active.

#### Step 2 — Install Python

Download Python 3.11 or higher from [https://www.python.org/downloads](https://www.python.org/downloads). During installation on Windows, check the box that says Add Python to PATH.

#### Step 3 — Install Grype

Download the latest Grype release from [https://github.com/anchore/grype/releases](https://github.com/anchore/grype/releases). On Windows, extract the zip and copy grype.exe to `C:\Windows\System32\`

Verify:

```
grype version
```

#### Step 4 — Install Ollama and the AI model

Download Ollama from [https://ollama.com/download](https://ollama.com/download) and install it. Then run:

```
ollama pull llama3.2
```

This downloads the 2GB model. Ollama must be running in the background for AI features to work.

#### Step 5 — Clone and install dependencies

```
git clone https://github.com/YOUR_USERNAME/docker-scanner.git
cd docker-scanner
python -m pip install docker streamlit dockerfile-parse reportlab matplotlib ollama
```

#### Step 6 — Run

```
python -m streamlit run app.py
```

Opens automatically at [http://localhost:8501](http://localhost:8501)

---

### Usage

#### Scanning a Docker image for CVEs

Make sure the image exists locally or is pullable from Docker Hub:

```
docker pull nginx:latest
```

Open the CVE Scan tab, type the image name, and click Scan. The first scan takes 1 to 2 minutes while Grype downloads its database. Subsequent scans are faster.

#### Scanning a Dockerfile

Open the Dockerfile Rules tab, paste your Dockerfile content or upload the file, and click Scan Dockerfile. Results appear instantly with no network requests required.

#### Running CIS checks

Open the CIS Benchmark tab, enter an image name or select a running container, and click Run CIS Checks.

#### Using the AI assistant

Run any scan first, then open the AI Chat Assistant tab. The assistant already has your scan findings as context. Click a quick question button or type your own question.

#### Starting a container for live monitoring

```
docker run -d --name test-nginx -p 8080:80 nginx:latest
```

Then open the Live Monitoring tab and select test-nginx from the dropdown.

---

### Test Cases

#### Insecure Dockerfile — triggers all critical rules

```dockerfile
FROM ubuntu:latest
RUN apt-get install nginx
ADD ./src /app
ENV DB_PASSWORD=admin123
ENV API_KEY=sk-abc123xyz
EXPOSE 22
EXPOSE 80
RUN curl https://get.docker.com | bash
CMD ["nginx", "-g", "daemon off;"]
```

Expected result: 8 to 10 violations, Risk Score near 100/100

#### Secure Dockerfile — should pass all rules

```dockerfile
FROM nginx:1.25.3
LABEL maintainer="your@email.com"
LABEL version="1.0"
WORKDIR /app
COPY ./src /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
USER nginx
EXPOSE 80
```

Expected result: 0 violations

#### Image CVE scan

```
docker pull nginx:latest
docker pull nginx:1.25.3-alpine
```

Scan both and use the Compare Images tab to see which is more secure.

---

### Project Structure

```
docker-scanner/
    app.py              Main Streamlit application — all 11 tabs
    scanner.py          Core scanning engine — Docker SDK, Grype, deduplication
    rules.py            12 Dockerfile security rules with STRIDE mapping
    cis.py              10 CIS Docker Benchmark checks
    ai_assistant.py     AI chat, executive summary, priority list
    monitoring.py       Live container resource statistics
    trends.py           Risk trend chart generation using matplotlib
    history.py          Scan history read and write
    report.py           PDF report generation using ReportLab
    scan_history.json   Auto-generated on first scan, stores last 20 scans
    README.md
```

---

### Technologies Used

| Technology |Version  |Purpose  |
| --- | --- | --- |
| Python | 3.11+ | Core language |
| Streamlit | 1.56.0 | Web UI framework |
| Docker SDK for Python | 7.1.0 | Connect to Docker Desktop |
| Grype | 0.111.1 | CVE vulnerability scanning |
| dockerfile-parse | 2.0.1 | Dockerfile instruction parsing |
| ReportLab | 4.4.10 | PDF report generation |
| Matplotlib | Latest | Risk trend chart generation |
| Ollama | Latest | Local AI model runtime |
| llama3.2 | 2GB | AI language model |

---

### Real World Test Results

Testing against nginx:latest (as of August 2026):

- 231 unique CVEs found after deduplication
- 3 Critical, 31 High, 67 Medium, 130 Low
- Risk Score: 100/100
- CIS Benchmark: 80% (8 passed, 2 failed)

Testing against nginx:1.25.3-alpine:

- 172 findings
- 12 Critical, 63 High, 83 Medium, 14 Low
- Despite more Critical findings, significantly smaller total attack surface due to minimal base

Image comparison nginx:latest vs strangebee/thehive:5:

- 110 CVEs unique to nginx:latest
- 119 CVEs unique to strangebee/thehive:5
- 160 CVEs shared between both
- Winner: strangebee/thehive:5 with fewer Critical findings (27 vs 36)

---

### Future Improvements

- Cloud deployment for SaaS access with user authentication
- CI/CD pipeline integration via REST API
- Real-time CVE alerts when new vulnerabilities affect previously scanned images
- Docker Compose and Kubernetes manifest scanning
- More precise STRIDE mapping using CWE classification
- Email notifications for critical findings
- Team workspace with shared scan history

---

### License

Open source, available for educational and commercial use.

---

### Author

Afan Tariq
 BS Cyber Security, Air University Islamabad
