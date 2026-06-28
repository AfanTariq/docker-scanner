# app.py — Docker Security Scanner — Complete Final Version with AI Features

import streamlit as st
import tempfile
import os
import time
from scanner import (
    connect_docker, get_local_images, get_running_containers,
    scan_image_with_grype, scan_dockerfile,
    calculate_risk_score, count_by_severity,
    get_fixable_findings, get_unfixable_findings,
    generate_secure_dockerfile
)
from cis import run_cis_checks_on_image, run_cis_checks_on_container, summarize_cis
from history import load_history, save_scan, delete_history
from report import generate_pdf_report
from ai_assistant import (
    check_ollama_available, build_findings_context,
    ask_ai_question, generate_executive_summary,
    generate_priority_list, generate_custom_fix
)
from monitoring import get_container_stats, init_metrics_buffer, append_metrics
from trends import (
    generate_risk_trend_chart, generate_severity_breakdown_chart,
    calculate_trend_stats
)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Docker Security Scanner",
    page_icon="🔒",
    layout="wide"
)

st.markdown("""
<style>
.main-header {
    background: linear-gradient(90deg, #1a1a2e, #16213e);
    padding: 20px 24px;
    border-radius: 12px;
    margin-bottom: 20px;
}
.fix-yes { background:#d4edda;color:#155724;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold; }
.fix-no  { background:#f8d7da;color:#721c24;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold; }
.chat-user { background:#e7f1ff;border-radius:10px;padding:10px 14px;margin:6px 0;max-width:80%;margin-left:auto; }
.chat-ai   { background:#f1f1f1;border-radius:10px;padding:10px 14px;margin:6px 0;max-width:80%; }
</style>
""", unsafe_allow_html=True)

# ── Connect Docker ────────────────────────────────────────────────────────────
client, error = connect_docker()

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
  <h1 style="margin:0;font-size:26px;color:white;">🔒 Docker Security Scanner</h1>
  <p style="margin:4px 0 0;opacity:.75;font-size:13px;color:white;">
    AI Powered Container Security Platform
  </p>
</div>
""", unsafe_allow_html=True)

if error:
    st.error(f"❌ Docker not connected: {error}")
    st.info("Make sure Docker Desktop is running then refresh.")
    st.stop()
else:
    st.success("✅ Docker Desktop connected and running")

ollama_ok, ollama_err = check_ollama_available()
if ollama_ok:
    st.success("🤖 AI Assistant (Ollama) connected and ready")
else:
    st.warning(
        f"⚠️ AI Assistant not available: {ollama_err}. "
        "Run 'ollama serve' in a terminal, or install from ollama.com"
    )

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🐳 Docker Environment")
    st.markdown("### 📦 Local Images")
    if client:
        for img in get_local_images(client):
            st.markdown(f"🐳 `{img['tag']}`")
            st.caption(f"{img['size_mb']} MB")
    st.markdown("---")
    st.markdown("### ▶️ Running Containers")
    if client:
        containers = get_running_containers(client)
        if containers:
            for c in containers:
                st.markdown(f"🟢 **{c['name']}**")
                st.caption(c['image'])
        else:
            st.info("No containers running")
    st.markdown("---")
    history = load_history()
    st.markdown("### 📊 Stats")
    st.metric("Total Scans", len(history))
    if history:
        st.metric("Last Score", f"{history[0]['risk_score']}/100")
    st.markdown("---")
    st.markdown("### 🤖 AI Status")
    st.markdown("Model: `llama3.2`" if ollama_ok else "Model: Not connected")


# ── Helpers ───────────────────────────────────────────────────────────────────
def sev_icon(sev):
    return {'Critical':'🔴','High':'🟠','Medium':'🟡',
            'Low':'🟢','Negligible':'⚪'}.get(sev,'⚪')


def render_metrics(findings):
    counts = count_by_severity(findings)
    score  = calculate_risk_score(findings)
    fixable = len(get_fixable_findings(findings))
    c1,c2,c3,c4,c5,c6 = st.columns(6)
    c1.metric("🔴 Critical", counts['Critical'])
    c2.metric("🟠 High",     counts['High'])
    c3.metric("🟡 Medium",   counts['Medium'])
    c4.metric("🟢 Low",      counts['Low'])
    c5.metric("⚠️ Score",   f"{score}/100")
    c6.metric("🔧 Fixable",  fixable)
    if score > 70:
        st.error(f"🔴 High Risk — Score {score}/100")
    elif score > 40:
        st.warning(f"🟠 Medium Risk — Score {score}/100")
    else:
        st.success(f"🟢 Low Risk — Score {score}/100")
    st.progress(score / 100)
    return counts, score


def render_findings(findings, prefix="x"):
    if not findings:
        st.success("✅ No findings!")
        return

    col1, col2, col3 = st.columns(3)
    with col1:
        stride_opts = ["All"] + sorted({f.get('stride','?') for f in findings})
        sel_stride  = st.selectbox("🎯 STRIDE", stride_opts, key=f"{prefix}_str")
    with col2:
        sev_opts = ["All","Critical","High","Medium","Low","Negligible"]
        sel_sev  = st.selectbox("⚠️ Severity", sev_opts, key=f"{prefix}_sev")
    with col3:
        fix_opts = ["All","Fixable only","No fix available"]
        sel_fix  = st.selectbox("🔧 Fix status", fix_opts, key=f"{prefix}_fix")

    filtered = findings
    if sel_stride != "All":
        filtered = [f for f in filtered if f.get('stride') == sel_stride]
    if sel_sev != "All":
        filtered = [f for f in filtered if f.get('severity') == sel_sev]
    if sel_fix == "Fixable only":
        filtered = [f for f in filtered if f.get('has_fix', False)]
    elif sel_fix == "No fix available":
        filtered = [f for f in filtered if not f.get('has_fix', False)]

    st.markdown(f"**{len(filtered)} findings shown**")
    st.divider()

    if not filtered:
        st.info("No findings match filters.")
        return

    for idx, f in enumerate(filtered):
        sev  = f.get('severity','Unknown')
        icon = sev_icon(sev)
        has_fix = f.get('has_fix', False)

        with st.expander(
            f"{icon} {f.get('rule','')} — {sev} | "
            f"STRIDE: {f.get('stride','')} | "
            f"{'✔ Fix available' if has_fix else '✘ No fix yet'}"
        ):
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("**🔍 Detail**")
                st.info(f.get('detail',''))
                st.markdown("**❓ Why**")
                st.warning(f.get('why','Security risk'))
                st.markdown(f"**🎯 STRIDE:** `{f.get('stride','')}`")
            with col_b:
                st.markdown("**✅ Fix**")
                if has_fix:
                    st.success(f"Update to: **{f.get('fix','')}**")
                else:
                    st.error("No fix released yet by vendor.")

                if f.get('bad_code') and f.get('good_code'):
                    st.markdown("**❌ Vulnerable**")
                    st.code(f['bad_code'], language='dockerfile')
                    st.markdown("**✅ Secure**")
                    st.code(f['good_code'], language='dockerfile')

            if ollama_ok:
                if st.button(
                    f"🤖 Ask AI for custom fix",
                    key=f"{prefix}_aifix_{idx}"
                ):
                    with st.spinner("AI generating custom fix..."):
                        fix_response, fix_err = generate_custom_fix(f)
                    if fix_err:
                        st.error(f"AI error: {fix_err}")
                    else:
                        st.markdown("**🤖 AI Generated Fix**")
                        st.markdown(fix_response)


def render_cis(results):
    if not results:
        st.warning("No CIS results.")
        return
    passed, failed = summarize_cis(results)
    total = len(results)
    pct   = round(passed / total * 100) if total else 0
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("✅ Passed", passed)
    c2.metric("❌ Failed", failed)
    c3.metric("📊 Total",  total)
    c4.metric("🏆 Score",  f"{pct}%")
    st.progress(pct / 100)
    st.divider()
    for r in results:
        status = r.get('status','PASS')
        icon   = "✅" if status == 'PASS' else "❌"
        with st.expander(f"{icon} {r.get('id','?')} — {r.get('title','')}"):
            ca, cb = st.columns(2)
            with ca:
                st.markdown(f"**Status:** {'✅ PASS' if status=='PASS' else '❌ FAIL'}")
                st.markdown(f"**STRIDE:** `{r.get('stride','')}`")
                if status == 'PASS':
                    st.success(r.get('detail',''))
                else:
                    st.error(r.get('detail',''))
            with cb:
                st.info(r.get('description',''))
                st.success(r.get('fix',''))


# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1,tab2,tab3,tab4,tab5,tab6,tab7,tab8,tab9,tab10,tab11 = st.tabs([
    "🔍 CVE Scan",
    "📄 Dockerfile Rules",
    "🛡️ CIS Benchmark",
    "🔄 Compare Images",
    "🏗️ Secure Dockerfile",
    "🤖 AI Chat Assistant",
    "📝 AI Summary",
    "📈 Live Monitoring",
    "📉 Risk Trends",
    "📊 Scan History",
    "📥 PDF Report"
])


# ════════════════════════════════════════════════════════════════════════════
# TAB 1 — CVE Scan
# ════════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("🔍 CVE Vulnerability Scanner")
    col1, col2 = st.columns([3,1])
    with col1:
        img_name = st.text_input("Image name", value="nginx:latest")
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        do_scan = st.button("🔍 Scan", use_container_width=True, type="primary")

    dedup = st.checkbox("Remove duplicate CVEs", value=True)

    if do_scan and img_name:
        with st.spinner(f"Scanning {img_name}..."):
            findings, err = scan_image_with_grype(img_name, deduplicate=dedup)
        if err:
            st.error(f"❌ {err}")
        elif not findings:
            st.success("✅ No CVEs found!")
        else:
            counts = count_by_severity(findings)
            score  = calculate_risk_score(findings)
            save_scan(img_name, "CVE Scan", findings, score, counts)
            st.session_state.update({
                'cve_findings': findings, 'cve_target': img_name,
                'cve_score': score, 'cve_counts': counts
            })
            st.success(f"✅ Found **{len(findings)}** vulnerabilities")

    if st.session_state.get('cve_findings'):
        findings = st.session_state['cve_findings']
        st.divider()
        render_metrics(findings)
        st.divider()
        render_findings(findings, prefix="cve")


# ════════════════════════════════════════════════════════════════════════════
# TAB 2 — Dockerfile Rules
# ════════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("📄 Dockerfile Static Analysis")
    method = st.radio("Input", ["Paste content","Upload file"], horizontal=True)

    df_content = None
    if method == "Paste content":
        df_text = st.text_area("Paste Dockerfile", height=180)
        if df_text.strip():
            df_content = df_text
    else:
        up = st.file_uploader("Upload Dockerfile", type=None)
        if up:
            df_content = up.read().decode('utf-8')
            st.code(df_content, language='dockerfile')

    if st.button("🔍 Scan Dockerfile", type="primary"):
        if not df_content:
            st.warning("Please paste or upload a Dockerfile.")
        else:
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='', prefix='Dockerfile_',
                delete=False, encoding='utf-8'
            ) as tmp:
                tmp.write(df_content)
                tmp_path = tmp.name
            findings, err = scan_dockerfile(tmp_path)
            try: os.unlink(tmp_path)
            except: pass

            if err:
                st.error(f"❌ {err}")
            elif not findings:
                st.success("✅ No violations!")
            else:
                counts = count_by_severity(findings)
                score  = calculate_risk_score(findings)
                save_scan("Dockerfile", "Dockerfile Scan", findings, score, counts)
                st.session_state.update({
                    'df_findings': findings, 'df_score': score, 'df_counts': counts
                })
                st.success(f"✅ Found **{len(findings)}** violations")

    if st.session_state.get('df_findings'):
        findings = st.session_state['df_findings']
        st.divider()
        render_metrics(findings)
        st.divider()
        render_findings(findings, prefix="df")


# ════════════════════════════════════════════════════════════════════════════
# TAB 3 — CIS Benchmark
# ════════════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("🛡️ CIS Docker Benchmark")
    cis_mode = st.radio("Check target", ["🖼️ Image", "▶️ Running Container"], horizontal=True)

    if "Image" in cis_mode:
        cis_img = st.text_input("Image name", value="nginx:latest", key="cis_img")
        if st.button("🛡️ Run CIS Checks", type="primary", key="cis_img_btn"):
            with st.spinner("Running checks..."):
                cis_res, cis_err = run_cis_checks_on_image(cis_img, client)
            if cis_err:
                st.error(f"❌ {cis_err}")
            else:
                st.session_state['cis_results'] = cis_res
                st.success("✅ Done")
    else:
        if client:
            running = get_running_containers(client)
            if running:
                names = [c['name'] for c in running]
                sel_cont = st.selectbox("Container", names)
                if st.button("🛡️ Run CIS Checks", type="primary", key="cis_con_btn"):
                    with st.spinner("Running checks..."):
                        cis_res, cis_err = run_cis_checks_on_container(sel_cont, client)
                    if cis_err:
                        st.error(f"❌ {cis_err}")
                    else:
                        st.session_state['cis_results'] = cis_res
                        st.success("✅ Done")
            else:
                st.info("No running containers.")

    if st.session_state.get('cis_results'):
        st.divider()
        render_cis(st.session_state['cis_results'])


# ════════════════════════════════════════════════════════════════════════════
# TAB 4 — Compare Images
# ════════════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("🔄 Compare Two Docker Images")
    col1, col2 = st.columns(2)
    with col1:
        img_a = st.text_input("Image A", value="nginx:latest", key="cmp_a_in")
    with col2:
        img_b = st.text_input("Image B", value="nginx:1.25.3-alpine", key="cmp_b_in")

    if st.button("🔄 Compare Images", type="primary"):
        col1, col2 = st.columns(2)
        with col1:
            with st.spinner(f"Scanning {img_a}..."):
                findings_a, err_a = scan_image_with_grype(img_a)
            findings_a = findings_a if not err_a else []
        with col2:
            with st.spinner(f"Scanning {img_b}..."):
                findings_b, err_b = scan_image_with_grype(img_b)
            findings_b = findings_b if not err_b else []

        st.session_state['cmp_a'] = {'name': img_a, 'findings': findings_a}
        st.session_state['cmp_b'] = {'name': img_b, 'findings': findings_b}

    if st.session_state.get('cmp_a') and st.session_state.get('cmp_b'):
        da = st.session_state['cmp_a']
        db = st.session_state['cmp_b']
        col1, col2 = st.columns(2)

        def cmp_metrics(findings, name):
            counts = count_by_severity(findings)
            score  = calculate_risk_score(findings)
            st.markdown(f"#### {name}")
            c1,c2,c3,c4 = st.columns(4)
            c1.metric("🔴", counts['Critical'])
            c2.metric("🟠", counts['High'])
            c3.metric("🟡", counts['Medium'])
            c4.metric("🟢", counts['Low'])
            st.metric("Score", f"{score}/100")
            st.progress(score/100)
            return score

        with col1:
            score_a = cmp_metrics(da['findings'], da['name'])
        with col2:
            score_b = cmp_metrics(db['findings'], db['name'])

        st.divider()
        if score_a < score_b:
            st.success(f"✅ **{da['name']}** is more secure")
        elif score_b < score_a:
            st.success(f"✅ **{db['name']}** is more secure")
        else:
            st.info("Equal risk scores.")


# ════════════════════════════════════════════════════════════════════════════
# TAB 5 — Secure Dockerfile Generator
# ════════════════════════════════════════════════════════════════════════════
with tab5:
    st.subheader("🏗️ Secure Dockerfile Generator")
    gen_base = st.text_input("Base image", value="nginx:latest")
    if st.button("🏗️ Generate", type="primary"):
        secure_df, pinned = generate_secure_dockerfile(gen_base)
        st.success(f"✅ Generated! `{gen_base}` → `{pinned}`")
        st.code(secure_df, language='dockerfile')
        st.download_button("⬇️ Download", secure_df, "Dockerfile.secure", "text/plain")


# ════════════════════════════════════════════════════════════════════════════
# TAB 6 — AI Chat Assistant (NEW)
# ════════════════════════════════════════════════════════════════════════════
with tab6:
    st.subheader("🤖 AI Security Chat Assistant")
    st.markdown(
        "Ask questions about your scan results in plain language. "
        "Powered by Ollama running locally — completely free and private."
    )

    if not ollama_ok:
        st.error(f"AI not available: {ollama_err}")
        st.info("Run `ollama serve` in a terminal window and refresh this page.")
    else:
        source = st.radio(
            "Chat about which scan?",
            ["Last CVE Scan", "Last Dockerfile Scan"],
            horizontal=True, key="chat_source"
        )

        chat_findings = []
        chat_target   = "Unknown"
        chat_type     = "Scan"
        chat_score    = 0

        if source == "Last CVE Scan" and st.session_state.get('cve_findings'):
            chat_findings = st.session_state['cve_findings']
            chat_target   = st.session_state.get('cve_target','Unknown')
            chat_type     = "CVE Scan"
            chat_score    = st.session_state.get('cve_score', 0)
        elif source == "Last Dockerfile Scan" and st.session_state.get('df_findings'):
            chat_findings = st.session_state['df_findings']
            chat_target   = "Dockerfile"
            chat_type     = "Dockerfile Scan"
            chat_score    = st.session_state.get('df_score', 0)

        if not chat_findings:
            st.warning(f"No {source.lower()} results yet. Run a scan first.")
        else:
            st.success(f"💬 Chatting about: **{chat_target}** — {len(chat_findings)} findings, Risk Score {chat_score}/100")

            if 'chat_messages' not in st.session_state:
                st.session_state['chat_messages'] = []

            for msg in st.session_state['chat_messages']:
                if msg['role'] == 'user':
                    st.markdown(f"<div class='chat-user'>🧑 {msg['content']}</div>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<div class='chat-ai'>🤖 {msg['content']}</div>", unsafe_allow_html=True)

            st.markdown("**Quick questions:**")
            qc1, qc2, qc3 = st.columns(3)
            quick_q = None
            with qc1:
                if st.button("Which to fix first?", use_container_width=True):
                    quick_q = "Which vulnerability should I fix first and why?"
            with qc2:
                if st.button("Explain top risk", use_container_width=True):
                    quick_q = "Explain the most critical finding in simple terms."
            with qc3:
                if st.button("Summarize risks", use_container_width=True):
                    quick_q = "Summarize the overall security risk in 3 sentences."

            user_q = st.chat_input("Ask a question about your scan results...")

            final_question = quick_q or user_q

            if final_question:
                st.session_state['chat_messages'].append({
                    'role': 'user', 'content': final_question
                })

                context = build_findings_context(
                    chat_findings, chat_target, chat_type, chat_score
                )

                with st.spinner("AI is thinking..."):
                    answer, err = ask_ai_question(
                        final_question, context,
                        chat_history=st.session_state['chat_messages'][:-1]
                    )

                if err:
                    st.error(f"AI error: {err}")
                else:
                    st.session_state['chat_messages'].append({
                        'role': 'assistant', 'content': answer
                    })
                    st.rerun()

            if st.button("🗑️ Clear Chat"):
                st.session_state['chat_messages'] = []
                st.rerun()


# ════════════════════════════════════════════════════════════════════════════
# TAB 7 — AI Summary (NEW)
# ════════════════════════════════════════════════════════════════════════════
with tab7:
    st.subheader("📝 AI Executive Summary & Priority List")
    st.markdown("AI generated plain-language summary for non-technical stakeholders.")

    if not ollama_ok:
        st.error(f"AI not available: {ollama_err}")
    else:
        source2 = st.radio(
            "Summarize which scan?",
            ["Last CVE Scan", "Last Dockerfile Scan"],
            horizontal=True, key="sum_source"
        )

        sum_findings = []
        sum_target   = "Unknown"
        sum_type     = "Scan"
        sum_score    = 0
        sum_counts   = {}

        if source2 == "Last CVE Scan" and st.session_state.get('cve_findings'):
            sum_findings = st.session_state['cve_findings']
            sum_target   = st.session_state.get('cve_target','Unknown')
            sum_type     = "CVE Scan"
            sum_score    = st.session_state.get('cve_score', 0)
            sum_counts   = st.session_state.get('cve_counts', {})
        elif source2 == "Last Dockerfile Scan" and st.session_state.get('df_findings'):
            sum_findings = st.session_state['df_findings']
            sum_target   = "Dockerfile"
            sum_type     = "Dockerfile Scan"
            sum_score    = st.session_state.get('df_score', 0)
            sum_counts   = st.session_state.get('df_counts', {})

        if not sum_findings:
            st.warning("No scan results yet.")
        else:
            col1, col2 = st.columns(2)
            with col1:
                if st.button("📝 Generate Executive Summary", type="primary", use_container_width=True):
                    with st.spinner("AI writing summary..."):
                        summary, err = generate_executive_summary(
                            sum_findings, sum_target, sum_type, sum_score, sum_counts
                        )
                    if err:
                        st.error(f"AI error: {err}")
                    else:
                        st.session_state['exec_summary'] = summary

            with col2:
                if st.button("🎯 Generate Priority List", type="primary", use_container_width=True):
                    with st.spinner("AI analyzing priorities..."):
                        priority, err = generate_priority_list(sum_findings)
                    if err:
                        st.error(f"AI error: {err}")
                    else:
                        st.session_state['priority_list'] = priority

            if st.session_state.get('exec_summary'):
                st.divider()
                st.markdown("### 📝 Executive Summary")
                st.info(st.session_state['exec_summary'])

            if st.session_state.get('priority_list'):
                st.divider()
                st.markdown("### 🎯 Top Priority Fixes")
                st.markdown(st.session_state['priority_list'])


# ════════════════════════════════════════════════════════════════════════════
# TAB 8 — Live Monitoring (NEW)
# ════════════════════════════════════════════════════════════════════════════
with tab8:
    st.subheader("📈 Live Container Resource Monitoring")
    st.markdown("Real time CPU, memory, and network stats for running containers.")

    if client:
        running = get_running_containers(client)
        if not running:
            st.info("No running containers. Start one with: docker run -d nginx:latest")
        else:
            names = [c['name'] for c in running]
            mon_container = st.selectbox("Select container to monitor", names)

            col1, col2 = st.columns([1,3])
            with col1:
                auto_refresh = st.checkbox("Auto refresh every 3s", value=False)
            with col2:
                manual_refresh = st.button("🔄 Refresh Now")

            if 'metrics_buffer' not in st.session_state:
                st.session_state['metrics_buffer'] = init_metrics_buffer()

            if manual_refresh or auto_refresh:
                stats, err = get_container_stats(client, mon_container)
                if err:
                    st.error(f"Error: {err}")
                else:
                    st.session_state['metrics_buffer'] = append_metrics(
                        st.session_state['metrics_buffer'], stats
                    )

                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("🖥️ CPU", f"{stats['cpu_percent']}%")
                    c2.metric("💾 Memory", f"{stats['mem_percent']}%")
                    c3.metric("📥 Net In", f"{stats['net_rx_mb']} MB")
                    c4.metric("📤 Net Out", f"{stats['net_tx_mb']} MB")

                    buf = st.session_state['metrics_buffer']
                    if len(buf['cpu']) > 1:
                        st.line_chart({
                            'CPU %': list(buf['cpu']),
                            'Memory %': list(buf['mem'])
                        })

            if auto_refresh:
                time.sleep(3)
                st.rerun()


# ════════════════════════════════════════════════════════════════════════════
# TAB 9 — Risk Trends (NEW)
# ════════════════════════════════════════════════════════════════════════════
with tab9:
    st.subheader("📉 Risk Trend Analysis")
    st.markdown("Track your security posture across all historical scans.")

    history = load_history()

    if len(history) < 2:
        st.info("Need at least 2 scans to show trends. Run more scans first.")
    else:
        stats = calculate_trend_stats(history)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("First Score", stats['first_score'])
        c2.metric("Latest Score", stats['last_score'])
        c3.metric("Average Score", stats['avg_score'])
        trend_icon = "📈" if stats['trend'] == "worsening" else "📉" if stats['trend'] == "improving" else "➡️"
        c4.metric(f"{trend_icon} Trend", stats['trend'].title())

        if stats['trend'] == 'improving':
            st.success(f"✅ Risk score improved by {abs(stats['change'])} points since first scan")
        elif stats['trend'] == 'worsening':
            st.warning(f"⚠️ Risk score increased by {stats['change']} points since first scan")
        else:
            st.info("Risk score has remained stable")

        st.divider()
        st.markdown("### Risk Score Over Time")
        chart_buf, err = generate_risk_trend_chart(history)
        if err:
            st.info(err)
        else:
            st.image(chart_buf, use_container_width=True)

        st.divider()
        st.markdown("### Severity Breakdown Over Time")
        chart_buf2, err2 = generate_severity_breakdown_chart(history)
        if err2:
            st.info(err2)
        else:
            st.image(chart_buf2, use_container_width=True)


# ════════════════════════════════════════════════════════════════════════════
# TAB 10 — Scan History
# ════════════════════════════════════════════════════════════════════════════
with tab10:
    st.subheader("📊 Scan History")
    col1, col2 = st.columns([3,1])
    with col2:
        if st.button("🗑️ Clear History", use_container_width=True):
            delete_history()
            st.success("Cleared.")
            st.rerun()

    history = load_history()
    if not history:
        st.info("No history yet.")
    else:
        for entry in history:
            score  = entry.get('risk_score', 0)
            s_icon = "🔴" if score > 70 else "🟠" if score > 40 else "🟢"
            with st.expander(
                f"{s_icon} [{entry.get('timestamp','')}] "
                f"{entry.get('target','')} — Score: {score}/100"
            ):
                c1,c2,c3,c4,c5 = st.columns(5)
                c1.metric("🔴", entry['counts'].get('Critical',0))
                c2.metric("🟠", entry['counts'].get('High',0))
                c3.metric("🟡", entry['counts'].get('Medium',0))
                c4.metric("🟢", entry['counts'].get('Low',0))
                c5.metric("Score", f"{score}/100")
                st.progress(score / 100)


# ════════════════════════════════════════════════════════════════════════════
# TAB 11 — PDF Report
# ════════════════════════════════════════════════════════════════════════════
with tab11:
    st.subheader("📥 PDF Security Report")
    report_src = st.radio(
        "Generate from",
        ["Last CVE Scan", "Last Dockerfile Scan"],
        horizontal=True
    )

    can_gen = False
    rep_findings, rep_target, rep_score, rep_counts, rep_type = [], "Unknown", 0, {}, "Scan"

    if report_src == "Last CVE Scan" and st.session_state.get('cve_findings'):
        rep_findings = st.session_state['cve_findings']
        rep_target   = st.session_state.get('cve_target','Unknown')
        rep_score    = st.session_state.get('cve_score', 0)
        rep_counts   = st.session_state.get('cve_counts', {})
        rep_type     = "CVE Vulnerability Scan"
        can_gen      = True
    elif report_src == "Last Dockerfile Scan" and st.session_state.get('df_findings'):
        rep_findings = st.session_state['df_findings']
        rep_target   = "Dockerfile"
        rep_score    = st.session_state.get('df_score', 0)
        rep_counts   = st.session_state.get('df_counts', {})
        rep_type     = "Dockerfile Static Analysis"
        can_gen      = True
    else:
        st.warning("Run a scan first.")

    if can_gen:
        st.divider()
        if st.button("📥 Generate PDF", type="primary"):
            with st.spinner("Building PDF..."):
                pdf_buf = generate_pdf_report(
                    rep_target, rep_findings, rep_score, rep_counts, rep_type
                )
            safe = rep_target.replace(':','_').replace('/','_').replace(' ','_')
            st.download_button(
                "⬇️ Download PDF Report", pdf_buf,
                f"security_report_{safe}.pdf", "application/pdf",
                use_container_width=True
            )
            st.success("✅ PDF ready!")
            st.balloons()

# ── Footer ────────────────────────────────────────────────────────────────────
st.divider()
c1,c2,c3 = st.columns(3)
c1.caption("🔒 Docker Security Scanner")
c2.caption("AI Powered with Ollama")
c3.caption("STRIDE Mapping | Grype | CIS Benchmark")