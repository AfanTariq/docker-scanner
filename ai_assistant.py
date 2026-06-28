# ai_assistant.py — AI chat assistant and summary generator using Ollama

import ollama
import json


MODEL_NAME = "llama3.2"


def build_findings_context(findings, scan_target, scan_type, risk_score):
    if not findings:
        return f"Scan target: {scan_target}\nScan type: {scan_type}\nNo findings detected."

    summary_lines = [
        f"Scan target: {scan_target}",
        f"Scan type: {scan_type}",
        f"Risk score: {risk_score}/100",
        f"Total findings: {len(findings)}",
        "",
        "Findings list:"
    ]

    for i, f in enumerate(findings[:60], 1):
        line = (
            f"{i}. [{f.get('severity','Unknown')}] {f.get('rule','')} "
            f"- STRIDE: {f.get('stride','Unknown')} "
            f"- Fix: {f.get('fix','No fix available')}"
        )
        summary_lines.append(line)

    if len(findings) > 60:
        summary_lines.append(f"... and {len(findings) - 60} more findings not shown")

    return "\n".join(summary_lines)


def ask_ai_question(question, findings_context, chat_history=None):
    system_prompt = (
        "You are a helpful security assistant analyzing Docker container "
        "vulnerability scan results. You have access to the scan data below. "
        "Answer questions clearly and concisely based only on this data. "
        "If asked which vulnerability to fix first, prioritize Critical and "
        "High severity items with available fixes. Keep answers under 150 words "
        "unless the user asks for detail.\n\n"
        f"SCAN DATA:\n{findings_context}"
    )

    messages = [{"role": "system", "content": system_prompt}]

    if chat_history:
        for msg in chat_history[-6:]:
            messages.append(msg)

    messages.append({"role": "user", "content": question})

    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=messages
        )
        return response['message']['content'], None
    except Exception as e:
        return None, str(e)


def generate_executive_summary(findings, scan_target, scan_type, risk_score, counts):
    context = build_findings_context(findings, scan_target, scan_type, risk_score)

    prompt = (
        "Write a short executive summary of this Docker security scan for a "
        "non technical manager or instructor. Cover the overall risk level, "
        "the most important issues found, and a one sentence recommendation. "
        "Keep it under 120 words, plain language, no bullet points, no markdown, "
        "professional tone.\n\n"
        f"{context}"
    )

    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}]
        )
        return response['message']['content'], None
    except Exception as e:
        return None, str(e)


def generate_priority_list(findings):
    if not findings:
        return None, "No findings to prioritize"

    findings_text = "\n".join([
        f"- [{f.get('severity','Unknown')}] {f.get('rule','')} "
        f"(STRIDE: {f.get('stride','')}, Fix: {f.get('fix','No fix available')})"
        for f in findings[:50]
    ])

    prompt = (
        "Given this list of Docker security findings, identify the top 5 "
        "most important issues to fix first. Consider severity, whether a fix "
        "is available, and the type of attack the STRIDE category represents. "
        "Respond as a numbered list of exactly 5 items, each with the finding "
        "name and a one sentence reason why it is high priority. Keep it concise.\n\n"
        f"{findings_text}"
    )

    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}]
        )
        return response['message']['content'], None
    except Exception as e:
        return None, str(e)


def check_ollama_available():
    try:
        ollama.list()
        return True, None
    except Exception as e:
        return False, str(e)


def generate_custom_fix(finding, dockerfile_content=None):
    context = (
        f"Finding: {finding.get('rule','')}\n"
        f"Severity: {finding.get('severity','')}\n"
        f"Detail: {finding.get('detail','')}\n"
        f"Generic fix: {finding.get('fix','')}"
    )

    if dockerfile_content:
        context += f"\n\nUser's actual Dockerfile:\n{dockerfile_content}"

    prompt = (
        "Generate the exact corrected Dockerfile line or block to fix this "
        "specific security finding. If the user's actual Dockerfile is provided, "
        "tailor the fix to their exact code. Respond with only the code fix, "
        "no explanation, wrapped in a dockerfile code block.\n\n"
        f"{context}"
    )

    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}]
        )
        return response['message']['content'], None
    except Exception as e:
        return None, str(e)