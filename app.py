# app.py — Docker Security Scanner — Complete Final Version with Advanced Features

import streamlit as st
import tempfile
import os
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
.stride-box {
    border: 0.5px solid #dee2e6;
    border-radius: 8px;
    padding: 10px 14px;
    margin-bottom: 8px;
}
.fix-yes {
    background: #d4edda;
    color: #155724;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: bold;
}
.fix-no {
    background: #f8d7da;
    color: #721c24;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

# ── Connect Docker ────────────────────────────────────────────────────────────
client, error = connect_docker()

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
  <h1 style="margin:0;font-size:26px;color:white;">🔒 Docker Security Scanner</h1>
  <p style="margin:4px 0 0;opacity:.75;font-size:13px;color:white;">
    CY256 — Secure Software Design and Development | Air University Islamabad
  </p>
</div>
""", unsafe_allow_html=True)

if error:
    st.error(f"❌ Docker not connected: {error}")
    st.info("Make sure Docker Desktop is running then refresh.")
    st.stop()
else:
    st.success("✅ Docker Desktop connected and running")

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🐳 Docker Environment")

    st.markdown("### 📦 Local Images")
    if client:
        images = get_local_images(client)
        for img in images:
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


def render_stride_info():
    with st.expander("ℹ️ STRIDE Threat Model Reference"):
        cols = st.columns(6)
        items = [
            ("S","Spoofing","Identity attacks"),
            ("T","Tampering","Data modification"),
            ("R","Repudiation","Audit issues"),
            ("I","Info Disclosure","Data exposure"),
            ("D","Denial of Service","Availability"),
            ("E","Elevation","Privilege escalation"),
        ]
        for col, (letter, name, desc) in zip(cols, items):
            col.markdown(f"**{letter}**")
            col.caption(f"{name}")
            col.caption(desc)


def render_findings(findings, prefix="x"):
    if not findings:
        st.success("✅ No findings!")
        return

    render_stride_info()
    st.divider()

    # ── Filters ──────────────────────────────────────────
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

    fixable_count   = len([f for f in filtered if f.get('has_fix', False)])
    unfixable_count = len(filtered) - fixable_count

    st.markdown(
        f"**{len(filtered)} findings shown** — "
        f"🔧 {fixable_count} fixable | "
        f"⏳ {unfixable_count} no fix yet"
    )
    st.divider()

    if not filtered:
        st.info("No findings match filters.")
        return

    for f in filtered:
        sev    = f.get('severity','Unknown')
        icon   = sev_icon(sev)
        has_fix = f.get('has_fix', False)
        fix_badge = (
            '<span class="fix-yes">✔ Fix available</span>'
            if has_fix else
            '<span class="fix-no">✘ No fix yet</span>'
        )

        with st.expander(
            f"{icon} {f.get('rule','')} — {sev} | "
            f"STRIDE: {f.get('stride','')} | "
            f"{'✔ Fix available' if has_fix else '✘ No fix yet'}"
        ):
            col_a, col_b = st.columns(2)

            with col_a:
                st.markdown("**🔍 Detail**")
                st.info(f.get('detail',''))
                st.markdown("**❓ Why it matters**")
                st.warning(f.get('why','Security risk'))
                st.markdown(f"**🎯 STRIDE:** `{f.get('stride','')}`")
                st.markdown(f"**⚠️ Severity:** `{sev}`")
                if f.get('cvss'):
                    st.markdown(f"**📊 CVSS Score:** `{f.get('cvss','N/A')}`")
                st.markdown(f"**🏗️ SDLC Phase:** `{f.get('sdlc_phase','')}`")

            with col_b:
                st.markdown("**✅ Fix**")
                if has_fix:
                    st.success(f"Update to version: **{f.get('fix','')}**")
                else:
                    st.error(
                        "No fix released yet by vendor. "
                        "Monitor CVE advisories and consider:"
                    )
                    st.markdown(
                        "- Use a minimal base image (alpine)\n"
                        "- Apply network segmentation\n"
                        "- Enable runtime security monitoring\n"
                        "- Check for vendor patches regularly"
                    )

                if f.get('bad_code') and f.get('good_code'):
                    st.markdown("**❌ Vulnerable**")
                    st.code(f['bad_code'], language='dockerfile')
                    st.markdown("**✅ Secure**")
                    st.code(f['good_code'], language='dockerfile')


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
    if pct >= 80:
        st.success(f"🟢 Good security posture — {pct}% passed")
    elif pct >= 50:
        st.warning(f"🟠 Moderate security posture — {pct}% passed")
    else:
        st.error(f"🔴 Poor security posture — {pct}% passed")
    st.progress(pct / 100)
    st.divider()
    for r in results:
        status = r.get('status','PASS')
        icon   = "✅" if status == 'PASS' else "❌"
        with st.expander(
            f"{icon} {r.get('id','?')} — {r.get('title','')} | "
            f"{sev_icon(r.get('severity','Low'))} {r.get('severity','')}"
        ):
            ca, cb = st.columns(2)
            with ca:
                st.markdown(f"**Status:** {'✅ PASS' if status=='PASS' else '❌ FAIL'}")
                st.markdown(f"**Severity:** `{r.get('severity','')}`")
                st.markdown(f"**STRIDE:** `{r.get('stride','')}`")
                if status == 'PASS':
                    st.success(r.get('detail',''))
                else:
                    st.error(r.get('detail',''))
            with cb:
                st.info(r.get('description',''))
                st.success(r.get('fix',''))


# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1,tab2,tab3,tab4,tab5,tab6,tab7 = st.tabs([
    "🔍 CVE Scan",
    "📄 Dockerfile Rules",
    "🛡️ CIS Benchmark",
    "🔄 Compare Images",
    "🏗️ Secure Dockerfile",
    "📊 Scan History",
    "📥 PDF Report"
])


# ════════════════════════════════════════════════════════════════════════════
# TAB 1 — CVE Scan
# ════════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("🔍 CVE Vulnerability Scanner")
    st.markdown(
        "Scans every package in a Docker image against **200,000+ known CVEs**. "
        "Findings are deduplicated and mapped to STRIDE threat categories."
    )

    col1, col2 = st.columns([3,1])
    with col1:
        img_name = st.text_input(
            "Image name", value="nginx:latest",
            placeholder="e.g. nginx:latest, mysql:8.0, ubuntu:22.04"
        )
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        do_scan = st.button("🔍 Scan", use_container_width=True, type="primary")

    dedup = st.checkbox("Remove duplicate CVEs", value=True,
        help="Same CVE affecting multiple packages counted once per package")

    if do_scan and img_name:
        with st.spinner(f"Scanning {img_name} — may take 1-2 mins first time..."):
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
                'cve_findings': findings,
                'cve_target':   img_name,
                'cve_score':    score,
                'cve_counts':   counts
            })
            st.success(f"✅ Found **{len(findings)}** unique vulnerabilities in `{img_name}`")

    if st.session_state.get('cve_findings'):
        findings = st.session_state['cve_findings']
        st.divider()

        # Fix availability summary
        fixable   = get_fixable_findings(findings)
        unfixable = get_unfixable_findings(findings)

        fa, fb = st.columns(2)
        with fa:
            st.info(
                f"🔧 **{len(fixable)} fixable** vulnerabilities — "
                "update the package to the listed version"
            )
        with fb:
            st.warning(
                f"⏳ **{len(unfixable)} with no fix yet** — "
                "vendor has not released a patch"
            )

        counts, score = render_metrics(findings)
        st.divider()
        render_findings(findings, prefix="cve")


# ════════════════════════════════════════════════════════════════════════════
# TAB 2 — Dockerfile Rules
# ════════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("📄 Dockerfile Static Analysis")
    st.markdown(
        "Checks your Dockerfile against **12 security rules** with "
        "STRIDE mapping, bad/good code examples, and SDLC phase tagging."
    )

    method = st.radio(
        "Input", ["Paste content","Upload file"], horizontal=True)

    df_content = None
    if method == "Paste content":
        df_text = st.text_area(
            "Paste Dockerfile",
            height=180,
            placeholder=(
                "FROM ubuntu:latest\n"
                "RUN apt-get install nginx\n"
                "ENV DB_PASSWORD=admin123\n"
                "EXPOSE 22\n"
            )
        )
        if df_text.strip():
            df_content = df_text
    else:
        up = st.file_uploader("Upload Dockerfile", type=None)
        if up:
            df_content = up.read().decode('utf-8')
            st.code(df_content, language='dockerfile')

    if st.button("🔍 Scan Dockerfile", type="primary"):
        if not df_content:
            st.warning("Please paste or upload a Dockerfile first.")
        else:
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='', prefix='Dockerfile_',
                delete=False, encoding='utf-8'
            ) as tmp:
                tmp.write(df_content)
                tmp_path = tmp.name

            findings, err = scan_dockerfile(tmp_path)
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

            if err:
                st.error(f"❌ {err}")
            elif not findings:
                st.success("✅ No violations — Dockerfile looks secure!")
            else:
                counts = count_by_severity(findings)
                score  = calculate_risk_score(findings)
                save_scan("Dockerfile", "Dockerfile Scan", findings, score, counts)
                st.session_state.update({
                    'df_findings': findings,
                    'df_score':    score,
                    'df_counts':   counts
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
    st.markdown(
        "Runs **10 official CIS Docker Security Benchmark** checks. "
        "Industry standard used by security teams worldwide."
    )

    with st.expander("ℹ️ What is CIS Docker Benchmark?"):
        st.markdown(
            "The **Center for Internet Security** publishes official Docker "
            "security benchmarks. These 10 checks cover: user config, "
            "health checks, privileges, network, resource limits, and filesystem."
        )

    cis_mode = st.radio(
        "Check target",
        ["🖼️ Image", "▶️ Running Container"],
        horizontal=True
    )

    if "Image" in cis_mode:
        cis_img = st.text_input(
            "Image name", value="nginx:latest", key="cis_img")
        if st.button("🛡️ Run CIS Checks", type="primary", key="cis_img_btn"):
            with st.spinner("Running CIS benchmark..."):
                cis_res, cis_err = run_cis_checks_on_image(cis_img, client)
            if cis_err:
                st.error(f"❌ {cis_err}")
            else:
                st.session_state['cis_results'] = cis_res
                p, f = summarize_cis(cis_res)
                st.success(f"✅ Done — {p} passed, {f} failed")
    else:
        if client:
            running = get_running_containers(client)
            if running:
                names    = [c['name'] for c in running]
                sel_cont = st.selectbox("Container", names)
                if st.button("🛡️ Run CIS Checks", type="primary", key="cis_con_btn"):
                    with st.spinner("Running CIS benchmark..."):
                        cis_res, cis_err = run_cis_checks_on_container(sel_cont, client)
                    if cis_err:
                        st.error(f"❌ {cis_err}")
                    else:
                        st.session_state['cis_results'] = cis_res
                        p, f = summarize_cis(cis_res)
                        st.success(f"✅ Done — {p} passed, {f} failed")
            else:
                st.info("No running containers. Start one first.")

    if st.session_state.get('cis_results'):
        st.divider()
        render_cis(st.session_state['cis_results'])


# ════════════════════════════════════════════════════════════════════════════
# TAB 4 — Compare Images (ADVANCED FEATURE)
# ════════════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("🔄 Compare Two Docker Images")
    st.markdown(
        "Scan two images side by side and compare their security posture. "
        "Useful for comparing base images or versions."
    )

    col1, col2 = st.columns(2)
    with col1:
        img_a = st.text_input(
            "Image A", value="nginx:latest", key="cmp_a")
    with col2:
        img_b = st.text_input(
            "Image B", value="nginx:1.25.3-alpine", key="cmp_b")

    if st.button("🔄 Compare Images", type="primary"):
        if not img_a or not img_b:
            st.warning("Please enter both image names.")
        else:
            col1, col2 = st.columns(2)
            with col1:
                with st.spinner(f"Scanning {img_a}..."):
                    findings_a, err_a = scan_image_with_grype(img_a)
                if err_a:
                    st.error(f"Image A error: {err_a}")
                    findings_a = []
                else:
                    st.success(f"✅ {img_a} — {len(findings_a)} findings")

            with col2:
                with st.spinner(f"Scanning {img_b}..."):
                    findings_b, err_b = scan_image_with_grype(img_b)
                if err_b:
                    st.error(f"Image B error: {err_b}")
                    findings_b = []
                else:
                    st.success(f"✅ {img_b} — {len(findings_b)} findings")

            st.session_state['cmp_data_a'] = {'name': img_a, 'findings': findings_a}
            st.session_state['cmp_data_b'] = {'name': img_b, 'findings': findings_b}

    if st.session_state.get('cmp_data_a') and st.session_state.get('cmp_data_b'):
        da = st.session_state['cmp_data_a']
        db = st.session_state['cmp_data_b']
        fa = da['findings']
        fb = db['findings']

        st.divider()
        st.markdown("### 📊 Side-by-Side Comparison")

        col1, col2 = st.columns(2)

        def comparison_metrics(findings, name):
            counts = count_by_severity(findings)
            score  = calculate_risk_score(findings)
            fixable = len(get_fixable_findings(findings))
            st.markdown(f"#### {name}")
            c1,c2,c3,c4 = st.columns(4)
            c1.metric("🔴 Critical", counts['Critical'])
            c2.metric("🟠 High",     counts['High'])
            c3.metric("🟡 Medium",   counts['Medium'])
            c4.metric("🟢 Low",      counts['Low'])
            st.metric("⚠️ Risk Score", f"{score}/100")
            st.metric("🔧 Fixable",    fixable)
            st.progress(score / 100)
            return score, counts

        with col1:
            score_a, counts_a = comparison_metrics(fa, da['name'])
        with col2:
            score_b, counts_b = comparison_metrics(fb, db['name'])

        st.divider()
        st.markdown("### 🏆 Verdict")
        if score_a < score_b:
            st.success(
                f"✅ **{da['name']}** is more secure "
                f"(Score: {score_a} vs {score_b})"
            )
        elif score_b < score_a:
            st.success(
                f"✅ **{db['name']}** is more secure "
                f"(Score: {score_b} vs {score_a})"
            )
        else:
            st.info("Both images have equal risk scores.")

        st.markdown("### 🔍 Unique CVEs in Each Image")
        cves_a = {f['cve_id'] for f in fa if 'cve_id' in f}
        cves_b = {f['cve_id'] for f in fb if 'cve_id' in f}
        only_a = cves_a - cves_b
        only_b = cves_b - cves_a
        both   = cves_a & cves_b

        col1, col2, col3 = st.columns(3)
        col1.metric(f"Only in {da['name']}", len(only_a))
        col2.metric("In both images",        len(both))
        col3.metric(f"Only in {db['name']}", len(only_b))

        if only_a:
            with st.expander(f"CVEs unique to {da['name']} ({len(only_a)})"):
                for cve in sorted(only_a):
                    st.markdown(f"- `{cve}`")
        if only_b:
            with st.expander(f"CVEs unique to {db['name']} ({len(only_b)})"):
                for cve in sorted(only_b):
                    st.markdown(f"- `{cve}`")


# ════════════════════════════════════════════════════════════════════════════
# TAB 5 — Secure Dockerfile Generator (ADVANCED FEATURE)
# ════════════════════════════════════════════════════════════════════════════
with tab5:
    st.subheader("🏗️ Secure Dockerfile Generator")
    st.markdown(
        "Automatically generates a security-hardened Dockerfile template "
        "based on your base image. Applies all 12 security rules by default."
    )

    gen_base = st.text_input(
        "Base image to secure",
        value="nginx:latest",
        placeholder="e.g. ubuntu, python, node, nginx"
    )

    col1, col2 = st.columns(2)
    with col1:
        include_healthcheck = st.checkbox("Include HEALTHCHECK", value=True)
        include_labels      = st.checkbox("Include LABEL metadata", value=True)
        include_workdir     = st.checkbox("Include WORKDIR", value=True)
    with col2:
        include_nonroot  = st.checkbox("Add non-root USER", value=True)
        include_cleanup  = st.checkbox("Include apt cleanup", value=True)
        include_comments = st.checkbox("Include security comments", value=True)

    if st.button("🏗️ Generate Secure Dockerfile", type="primary"):
        if not gen_base:
            st.warning("Enter a base image name first.")
        else:
            secure_df, pinned_base = generate_secure_dockerfile(gen_base)

            st.success(
                f"✅ Secure Dockerfile generated! "
                f"Base image pinned: `{gen_base}` → `{pinned_base}`"
            )

            st.markdown("### Generated Secure Dockerfile")
            st.code(secure_df, language='dockerfile')

            st.download_button(
                label="⬇️ Download Secure Dockerfile",
                data=secure_df,
                file_name="Dockerfile.secure",
                mime="text/plain",
                use_container_width=True
            )

            st.divider()
            st.markdown("### ✅ Security Rules Applied")
            rules_applied = []
            if include_nonroot:
                rules_applied.append("✅ Rule 1 — Non-root USER added")
            rules_applied.append("✅ Rule 3 — Port 22 not exposed")
            rules_applied.append("✅ Rule 4 — COPY used instead of ADD")
            if pinned_base != gen_base:
                rules_applied.append(
                    f"✅ Rule 5 — Image pinned ({gen_base} → {pinned_base})")
            if include_healthcheck:
                rules_applied.append("✅ Rule 6 — HEALTHCHECK included")
            if include_cleanup:
                rules_applied.append(
                    "✅ Rule 7 — --no-install-recommends + cleanup")
            if include_workdir:
                rules_applied.append("✅ Rule 11 — WORKDIR set to /app")
            if include_labels:
                rules_applied.append("✅ Rule 12 — LABEL metadata added")

            for r in rules_applied:
                st.markdown(r)

            st.info(
                "💡 **Next step:** Scan this Dockerfile using the "
                "Dockerfile Rules tab to verify it passes all checks!"
            )


# ════════════════════════════════════════════════════════════════════════════
# TAB 6 — Scan History
# ════════════════════════════════════════════════════════════════════════════
with tab6:
    st.subheader("📊 Scan History")
    st.markdown("Last 20 scans saved automatically. Track security improvement over time.")

    col1, col2 = st.columns([3,1])
    with col2:
        if st.button("🗑️ Clear History", use_container_width=True):
            delete_history()
            st.success("Cleared.")
            st.rerun()

    history = load_history()

    if not history:
        st.info("No history yet. Run a scan first.")
    else:
        st.markdown(f"**{len(history)} scans on record**")
        st.divider()
        for entry in history:
            score  = entry.get('risk_score', 0)
            s_icon = "🔴" if score > 70 else "🟠" if score > 40 else "🟢"
            with st.expander(
                f"{s_icon} [{entry.get('timestamp','')}] "
                f"{entry.get('target','')} — Score: {score}/100 | "
                f"{entry.get('total',0)} findings | {entry.get('type','')}"
            ):
                c1,c2,c3,c4,c5 = st.columns(5)
                c1.metric("🔴 Critical", entry['counts'].get('Critical',0))
                c2.metric("🟠 High",     entry['counts'].get('High',0))
                c3.metric("🟡 Medium",   entry['counts'].get('Medium',0))
                c4.metric("🟢 Low",      entry['counts'].get('Low',0))
                c5.metric("⚠️ Score",    f"{score}/100")
                st.progress(score / 100)
                for f in entry.get('findings', [])[:5]:
                    st.markdown(
                        f"{sev_icon(f.get('severity',''))} "
                        f"`{f.get('rule','')}` — "
                        f"STRIDE: **{f.get('stride','')}**"
                    )


# ════════════════════════════════════════════════════════════════════════════
# TAB 7 — PDF Report
# ════════════════════════════════════════════════════════════════════════════
with tab7:
    st.subheader("📥 PDF Security Report")
    st.markdown(
        "Generate a professional PDF containing full findings, "
        "STRIDE breakdown, risk score, and fix recommendations."
    )

    report_src = st.radio(
        "Generate from",
        ["Last CVE Scan", "Last Dockerfile Scan"],
        horizontal=True
    )

    can_gen     = False
    rep_findings = []
    rep_target   = "Unknown"
    rep_score    = 0
    rep_counts   = {}
    rep_type     = "Security Scan"

    if report_src == "Last CVE Scan":
        if st.session_state.get('cve_findings'):
            rep_findings = st.session_state['cve_findings']
            rep_target   = st.session_state.get('cve_target','Unknown')
            rep_score    = st.session_state.get('cve_score', 0)
            rep_counts   = st.session_state.get('cve_counts', {})
            rep_type     = "CVE Vulnerability Scan"
            can_gen      = True
        else:
            st.warning("Run a CVE scan first.")
    else:
        if st.session_state.get('df_findings'):
            rep_findings = st.session_state['df_findings']
            rep_target   = "Dockerfile"
            rep_score    = st.session_state.get('df_score', 0)
            rep_counts   = st.session_state.get('df_counts', {})
            rep_type     = "Dockerfile Static Analysis"
            can_gen      = True
        else:
            st.warning("Run a Dockerfile scan first.")

    if can_gen:
        fixable = len(get_fixable_findings(rep_findings))
        st.divider()
        c1,c2,c3,c4 = st.columns(4)
        c1.metric("Target",    rep_target)
        c2.metric("Findings",  len(rep_findings))
        c3.metric("Risk Score",f"{rep_score}/100")
        c4.metric("Fixable",   fixable)

        st.markdown("**Report includes:**")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("✅ Scan summary and metadata")
            st.markdown("✅ STRIDE threat breakdown table")
            st.markdown("✅ Risk score explanation")
        with col2:
            st.markdown("✅ Full findings sorted by severity")
            st.markdown("✅ Fix version per CVE")
            st.markdown("✅ Air University branding")

        st.divider()
        if st.button("📥 Generate PDF", type="primary"):
            with st.spinner("Building PDF..."):
                try:
                    pdf_buf = generate_pdf_report(
                        rep_target, rep_findings,
                        rep_score, rep_counts, rep_type
                    )
                    safe = (
                        rep_target
                        .replace(':','_').replace('/','_').replace(' ','_')
                    )
                    st.download_button(
                        label="⬇️ Download PDF Report",
                        data=pdf_buf,
                        file_name=f"security_report_{safe}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
                    st.success("✅ PDF ready — click above to download!")
                    st.balloons()
                except Exception as e:
                    st.error(f"❌ PDF error: {e}")

# ── Footer ────────────────────────────────────────────────────────────────────
st.divider()
c1,c2,c3 = st.columns(3)
c1.caption("🔒 Docker Security Scanner")
c2.caption("CY256 — Air University Islamabad")
c3.caption("STRIDE Mapping | Grype CVE Engine | CIS Benchmark")