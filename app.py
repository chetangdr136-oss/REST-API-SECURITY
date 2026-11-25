import streamlit as st
from scanner import assess
from report import make_pdf
import json

st.set_page_config(page_title="REST API Security Assessment", page_icon="🛡️", layout="wide")
st.title("🛡️ REST API Security Assessment")
st.caption("Python-based educational security checker | Use only on APIs you own or are authorized to assess.")

with st.sidebar:
    st.header("Assessment settings")
    target = st.text_input("API base URL", "http://127.0.0.1:5001")
    token = st.text_input("Optional Bearer test token", type="password")
    burst = st.slider("Small rate-limit probe requests", 1, 8, 5)
    st.info("Start the included demo API in another terminal before assessing localhost:5001.")

if st.button("Run assessment", type="primary"):
    with st.spinner("Running low-impact checks..."):
        result = assess(target, token or None, burst)
    st.session_state["assessment_result"] = result

result = st.session_state.get("assessment_result")
if result:
    findings = result.get("findings", [])
    high = sum(f["severity"] == "High" for f in findings)
    medium = sum(f["severity"] == "Medium" for f in findings)
    low = sum(f["severity"] == "Low" for f in findings)
    info = sum(f["severity"] == "Info" for f in findings)
    st.subheader("Assessment summary")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("High", high)
    c2.metric("Medium", medium)
    c3.metric("Low", low)
    c4.metric("Informational", info)
    st.write(f"**Target:** {result['target']}  |  **Time:** {result['timestamp']}")
    st.subheader("Detailed findings")
    for i, f in enumerate(findings, 1):
        with st.expander(f"{i}. {f['check']} — {f['severity']} / {f['status']}", expanded=f["severity"] in ("High", "Medium")):
            st.write("**Evidence:**", f["evidence"])
            st.write("**Recommendation:**", f["recommendation"])
    st.download_button("Download PDF report", make_pdf(result),
                       file_name="REST_API_Security_Assessment_Report.pdf",
                       mime="application/pdf")
    st.download_button("Download JSON results", json.dumps(result, indent=2),
                       file_name="assessment.json", mime="application/json")
else:
    st.markdown("""
    ### How to demonstrate
    1. Start the local demo API using `python demo_api.py`.
    2. Keep that terminal open.
    3. Start this dashboard using `streamlit run app.py`.
    4. Click **Run assessment**.
    5. Open the authentication finding to show that `/api/profile` returned HTTP 200 without a token.
    6. Download the PDF report and explain the recommended fixes.
    """)
