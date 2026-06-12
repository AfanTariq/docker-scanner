# Docker Security Scanner

A comprehensive Docker container security scanning tool that combines CVE vulnerability scanning, Dockerfile static analysis, and STRIDE threat model mapping in a single web-based interface. Built with Python and Streamlit.

---

## What Makes This Tool Different

Most security scanners like Trivy and Grype output raw CVE lists. Developers struggle to understand which vulnerabilities matter most and what type of attack they enable. This tool solves that by mapping every single finding to a STRIDE threat category, giving developers actionable intelligence instead of just a list of CVE IDs.

| Feature | Trivy | Grype | Snyk | This Tool |
|---|---|---|---|---|
| CVE Scanning | Yes | Yes | Yes | Yes |
| Dockerfile Rules | Yes | No | Yes | Yes |
| STRIDE Mapping | No | No | No | Yes |
| STRIDE Weighted Score | No | No | No | Yes |
| Filter by STRIDE | No | No | No | Yes |
| Fix Availability Filter | No | No | Partial | Yes |
| Image Comparison | No | No | No | Yes |
| Secure Dockerfile Generator | No | No | No | Yes |
| Free and Open Source | Yes | Yes | No | Yes |

---

## Features

### Tab 1 - CVE Vulnerability Scanner
- Scans every package inside a Docker image against 200,000+ known CVEs
- Uses Grype as the scanning engine
- Deduplicates results so the same CVE is not shown multiple times
- Maps every CVE to a STRIDE threat category based on severity
- Shows fix version where available
- Filter by STRIDE category, severity, and fix availability
- Calculates a weighted risk score using CVSS scores

### Tab 2 - Dockerfile Static Analysis
- Checks Dockerfile against 12 security rules
- Each violation shows bad code and secure fixed code
- STRIDE category mapped to each violation
- SDLC phase tagged per finding (Requirements, Design, Implementation, Testing)
- Supports paste or file upload

### Tab 3 - CIS Docker Benchmark
- Runs 10 official Center for Internet Security Docker Benchmark checks
- Works on both images and running containers
- Pass/fail status with percentage score
- Each check maps to a STRIDE category with fix instructions

### Tab 4 - Image Comparison
- Scan two Docker images side by side
- Compare risk scores, severity counts, and fixable vulnerabilities
- Shows CVEs unique to each image and CVEs shared between both
- Automatic verdict on which image is more secure

### Tab 5 - Secure Dockerfile Generator
- Generates a security-hardened Dockerfile template from any base image
- Automatically pins unpinned tags to specific stable versions
- Applies all 12 security rules by default
- Download the generated Dockerfile directly

### Tab 6 - Scan History
- Every scan is saved automatically
- Last 20 scans stored with timestamps and scores
- Track security improvement over time
- View top findings from any previous scan

### Tab 7 - PDF Report
- One-click PDF report generation using ReportLab
- Includes scan summary, risk score, STRIDE breakdown table
- Full findings table sorted by severity
- Fix recommendations per finding

---

## STRIDE Threat Model Mapping

Every finding in this tool is tagged with one of the six STRIDE categories:

| Category | Description | Example in Docker |
|---|---|---|
| Spoofing | Identity impersonation attacks | SSH port 22 exposed |
| Tampering | Data or code modification | Unpinned image tags |
| Repudiation | Audit trail and logging issues | No LABEL metadata |
| Information Disclosure | Unauthorized data exposure | Hardcoded secrets in ENV |
| Denial of Service | Availability disruption | No HEALTHCHECK defined |
| Elevation of Privilege | Unauthorized access escalation | Running as root user |

---

## The 12 Dockerfile Security Rules

| Rule | Severity | STRIDE Category | What It Checks |
|---|---|---|---|
| Rule 1 | Critical | Elevation of Privilege | No root USER directive |
| Rule 2 | Critical | Information Disclosure | Hardcoded secrets in ENV |
| Rule 3 | Critical | Spoofing | SSH port 22 exposed |
| Rule 4 | Critical | Tampering | ADD used instead of COPY |
| Rule 5 | High | Tampering | Unpinned or latest image tag |
| Rule 6 | High | Denial of Service | No HEALTHCHECK defined |
| Rule 7 | High | Elevation of Privilege | apt-get without no-install-recommends |
| Rule 8 | High | Tampering | curl or wget piped to bash |
| Rule 9 | High | Tampering | apt-get install without apt-get update |
| Rule 10 | Medium | Information Disclosure | Sensitive files copied into image |
| Rule 11 | Low | Tampering | No WORKDIR set |
| Rule 12 | Low | Repudiation | No LABEL metadata |

---

## Risk Scoring Formula

The risk score is calculated by summing severity weights across all findings and capping at 100.

```
Critical  = 40 points each
High      = 20 points each
Medium    = 10 points each
Low       =  5 points each
```

This weighting is STRIDE-aware. Critical findings that enable Elevation of Privilege attacks carry the most weight because they represent the highest impact threat category in container environments.

---

## Project Structure

```
docker-scanner/
    app.py              Main Streamlit web application with all 7 tabs
    scanner.py          Core scanning engine using Docker SDK and Grype
    rules.py            12 Dockerfile security rules with remediation details
    cis.py              10 CIS Docker Benchmark checks
    history.py          Scan history saving and loading
    report.py           PDF report generation using ReportLab
    scan_history.json   Auto-generated scan history file
    README.md
```

---

## Requirements

- Windows 10 or 11 (also works on Linux and macOS)
- Docker Desktop installed and running
- Python 3.11 or higher
- Grype vulnerability scanner

---

## Installation

### Step 1 - Install Docker Desktop

Download from https://www.docker.com/products/docker-desktop and install. Make sure it is running before using this tool. You will see the whale icon in your taskbar when it is active.

### Step 2 - Install Python

Download Python 3.11 or higher from https://www.python.org/downloads. During installation check the box that says "Add Python to PATH".

### Step 3 - Install Grype

Download the latest Grype release for Windows from https://github.com/anchore/grype/releases. Look for the file named grype_X.X.X_windows_amd64.zip, extract it, and copy grype.exe to C:\Windows\System32\

Verify installation:
```
grype version
```

### Step 4 - Clone the Repository

```
git clone https://github.com/AfanTariq/docker-scanner.git
cd docker-scanner
```

### Step 5 - Install Python Dependencies

```
python -m pip install docker streamlit dockerfile-parse reportlab
```

### Step 6 - Run the Tool

```
python -m streamlit run app.py
```

The tool will automatically open in your browser at http://localhost:8501

---

## Usage

### Scanning a Docker Image for CVEs

1. Make sure Docker Desktop is running
2. Open the CVE Scan tab
3. Type an image name such as nginx:latest or mysql:8.0
4. Click Scan Image
5. Wait 1 to 2 minutes on first run while Grype downloads its database
6. Filter results by STRIDE category, severity, or fix availability

### Scanning a Dockerfile

1. Open the Dockerfile Rules tab
2. Paste your Dockerfile content or upload the file
3. Click Scan Dockerfile
4. Results appear instantly with bad code and secure code examples

### Running CIS Benchmark Checks

1. Open the CIS Benchmark tab
2. Enter an image name or select a running container
3. Click Run CIS Checks
4. View pass/fail results with explanations and fixes

### Comparing Two Images

1. Open the Compare Images tab
2. Enter two image names such as nginx:latest and nginx:1.25.3-alpine
3. Click Compare Images
4. View side by side risk scores and unique CVEs per image

### Generating a Secure Dockerfile

1. Open the Secure Dockerfile tab
2. Enter your base image name
3. Click Generate Secure Dockerfile
4. Download the generated file and scan it to verify it passes all rules

### Downloading a PDF Report

1. Run any scan first
2. Open the PDF Report tab
3. Select which scan to generate the report from
4. Click Generate PDF and download

---

## Test Cases

### Test Case 1 - Insecure Dockerfile

Paste this in the Dockerfile Rules tab to see maximum findings:

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

Expected result: 8 to 10 violations, Risk Score 100/100

### Test Case 2 - Secure Dockerfile

```dockerfile
FROM nginx:1.25.3
LABEL maintainer="your@email.com"
LABEL version="1.0"
WORKDIR /app
COPY ./src /app
RUN apt-get update && apt-get install -y --no-install-recommends curl
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
USER nginx
EXPOSE 80
```

Expected result: 0 violations

### Test Case 3 - Image CVE Scan

Pull and scan nginx to see real vulnerabilities:
```
docker pull nginx:latest
```
Then scan in the CVE Scan tab. Expected result: 200+ CVEs with STRIDE mapping.

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.11 | Core programming language |
| Streamlit | Web UI framework |
| Docker SDK for Python | Connect to Docker Desktop |
| Grype | CVE vulnerability database scanning |
| dockerfile-parse | Dockerfile instruction parsing |
| ReportLab | PDF report generation |
| Docker Desktop | Container runtime |

---

## Future Improvements

- Cloud deployment for SaaS access
- User authentication and team workspaces
- CI/CD pipeline integration via REST API
- Real-time container monitoring
- Email alerts for critical CVEs
- Support for Docker Compose file scanning
- Integration with GitHub Actions

---

## License

This project is open source and available for educational use.

---

## Author

Afan Tariq
BS Cyber Security, Air University Islamabad
