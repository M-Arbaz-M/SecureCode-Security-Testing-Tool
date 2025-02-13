import os
import openai
import streamlit as st
from streamlit_ace import st_ace
from dotenv import load_dotenv
from user_controller import UserController
from vulnerability_service import VulnerabilityService
from vulnerability_service import MalwareService
from report_service import ReportService
from user_model import UserModel
from vulnerability_free_code import VulnerabilityFreeCode, rewrite_code_with_openai
from streamlit_option_menu import option_menu
from datetime import datetime, timedelta
import re


def load_css():
    with open('static/style.css') as f:
        css_code = f.read()
    st.markdown(f'<style>{css_code}</style>', unsafe_allow_html=True)


# Load environment variables

openai.api_key = st.secrets["OPENAI_API_KEY"]

# Initialize session state variables
session_vars = {
    'logged_in': False,
    'vulnerability_report': "",
    'last_user_code': "",
    'fixed_code': "",
    'issue_resolved': False,
    'user_id': None,
    'selected_issues': {},
    'issues_selected': False,
    'show_resolve_button': False,
    'scan_complete': False,
    'malware_result': None,
    'scan_type': 'Check Vulnerability'
}
for key, value in session_vars.items():
    if key not in st.session_state:
        st.session_state[key] = value

user_model = UserModel()
vulnerability_service = VulnerabilityService()
malware_service = MalwareService()
user_controller = UserController(user_model, vulnerability_service)
report_service = ReportService()


def parse_vulnerabilities(vulnerability_report):
    """Parse individual issues from the vulnerability report."""
    issues = re.findall(
        r'>> Issue: (.*?)\n\s+Severity: (.*?)\s+Confidence: (.*?)\n\s+Location: (.*?)\n', vulnerability_report, re.DOTALL)
    return [
        f"Issue: {desc}\nSeverity: {sev} | Confidence: {conf} | Location: {loc}"
        for desc, sev, conf, loc in issues
    ]


def update_issues_selected():
    """Update issues_selected flag based on selected issues."""
    st.session_state['issues_selected'] = any(
        st.session_state['selected_issues'].values())
    st.session_state['show_resolve_button'] = st.session_state['issues_selected']


def is_unique_title(user_id, title):
    """Check if the title is unique for the user."""
    existing_titles = [code[0]
                       for code in user_model.get_recent_codes(user_id)]
    return title not in existing_titles


def show_recent_codes_on_main(user_id):
    """Display recent code submissions with filters."""
    with st.container():
        st.subheader("Recent Code Submissions")

        col1, col2, col3 = st.columns([0.5, 0.25, 0.25])
        with col1:
            search_query = st.text_input("Search by title or code content")
        with col2:
            start_date = st.date_input("Start Date", value=None)
        with col3:
            end_date = st.date_input("End Date", value=None)

        if start_date and end_date and start_date > end_date:
            st.error("Start Date cannot be later than End Date.")
            return

        recent_codes = user_model.get_recent_codes(user_id)
        if not recent_codes:
            st.write("No recent submissions.")
            return

        today = datetime.now().date()
        grouped_codes = {
            "Today": [],
            "Yesterday": [],
            "Previous 7 Days": [],
            "Previous 30 Days": [],
            "Older": []
        }

        for title, input_code, output_code, created_at in recent_codes:
            submission_date = datetime.strptime(
                str(created_at), '%Y-%m-%d %H:%M:%S.%f').date()
            if (not search_query or search_query.lower() in title.lower() or
                    search_query.lower() in input_code.lower()):
                if submission_date == today:
                    grouped_codes["Today"].append(
                        (title, input_code, output_code, created_at))
                elif submission_date == today - timedelta(days=1):
                    grouped_codes["Yesterday"].append(
                        (title, input_code, output_code, created_at))
                elif today - timedelta(days=7) <= submission_date < today:
                    grouped_codes["Previous 7 Days"].append(
                        (title, input_code, output_code, created_at))
                elif today - timedelta(days=30) <= submission_date < today - timedelta(days=7):
                    grouped_codes["Previous 30 Days"].append(
                        (title, input_code, output_code, created_at))
                else:
                    grouped_codes["Older"].append(
                        (title, input_code, output_code, created_at))

        for group, codes in grouped_codes.items():
            if codes:
                st.subheader(group)
                for title, input_code, output_code, created_at in codes:
                    with st.expander(f"{title} on {created_at.strftime('%Y-%m-%d')}"):
                        st.write("**Input Code:**")
                        st.code(input_code, language="python")
                        st.write("**Output Code:**")
                        st.write(output_code)


def display_malware_result(result, file_content):
    """Display VirusTotal results with enhanced visualization"""
    if not result:
        return

    if 'error' in result:
        st.error(f"VirusTotal Error: {result['error']}")
        return

    data = result.get('data', {})
    attributes = data.get('attributes', {})
    results = attributes.get('last_analysis_results', {})

    # Manually calculate statistics
    stats = {
        'malicious': 0,
        'suspicious': 0,
        'harmless': 0,
        'undetected': 0
    }

    for engine_result in results.values():
        category = engine_result.get('category', 'undetected').lower()
        if category == 'malicious':
            stats['malicious'] += 1
        elif category == 'suspicious':
            stats['suspicious'] += 1
        elif category == 'harmless':
            stats['harmless'] += 1
        else:
            stats['undetected'] += 1

    if not results:
        st.warning("""
        No analysis results available. This could mean:
        1. Analysis is still in progress (wait longer)
        2. File was not properly scanned
        3. API limits reached
        """)
        return

    st.subheader("🛡️ SecureCode Analysis Report")

    # Verification check
    local_hash = malware_service.get_local_sha256(file_content)
    vt_hash = attributes.get('sha256')

    # File metadata section
    with st.expander("📄 File Metadata"):
        cols = st.columns(3)
        cols[0].metric("SHA256", vt_hash[:16] + "..." if vt_hash else "N/A")
        cols[1].metric("File Type", attributes.get(
            'type_description', 'Unknown'))
        cols[2].metric("First Submission", attributes.get(
            'first_submission_date', 'N/A'))

    # Detection summary with icons and colors
    st.write("### 🔍 Detection Summary")
    cols = st.columns(4)
    cols[0].metric("Malicious", stats['malicious'],
                   help="Number of engines detecting malware",
                   delta_color="off")
    cols[1].metric("Suspicious", stats['suspicious'],
                   help="Number of engines detecting suspicious activity",
                   delta_color="off")
    cols[2].metric("Undetected", stats['undetected'],
                   help="Number of engines with no detection",
                   delta_color="off")
    cols[3].metric("Harmless", stats['harmless'],
                   help="Number of engines detecting as safe",
                   delta_color="off")

    # Detailed threat breakdown
    if stats['malicious'] + stats['suspicious'] + stats['undetected'] > 0:
        st.write("### ⚠️ Analysis Details")
        with st.expander("View Full Engine Reports", expanded=True):
            for engine, data in results.items():
                category = data.get('category', 'undetected').lower()
                verdict = data.get('result', 'No verdict')
                malware_name = data.get('result', '')

                # Create colored tag based on category
                tag_color = {
                    'malicious': '#ff4b4b',
                    'suspicious': '#ffa500',
                    'undetected': '#7f8c8d',
                    'harmless': '#2ecc71'
                }.get(category, 'gray')

                # Display engine card
                with st.container(border=True):
                    cols = st.columns([1, 4])
                    with cols[0]:
                        st.markdown(f"""
                        <div style="
                            background: {tag_color}20;
                            border: 1px solid {tag_color};
                            color: {tag_color};
                            padding: 0.5rem;
                            border-radius: 8px;
                            text-align: center;
                        ">
                            <div style="font-size: 0.8rem;">{category.upper()}</div>
                            <div style="font-size: 1.2rem; font-weight: bold;">{engine}</div>
                        </div>
                        """, unsafe_allow_html=True)

                    with cols[1]:
                        # Display malware name if available
                        if category in ['malicious', 'suspicious'] and malware_name.lower() not in ['clean', 'unrated', '']:
                            st.markdown(f"""
                            <div style="
                                background: #ff4b4b20;
                                border: 1px solid #ff4b4b;
                                color: #ff4b4b;
                                padding: 0.25rem 0.5rem;
                                border-radius: 4px;
                                display: inline-block;
                                margin-bottom: 0.5rem;
                            ">
                                🦠 {malware_name}
                            </div>
                            """, unsafe_allow_html=True)

                        st.write(f"**Verdict:** {verdict}")
                        st.write(f"**Method:** {data.get('method', 'N/A')}")
                        st.write(
                            f"**Engine Version:** {data.get('engine_version', 'N/A')}")
                        st.write(
                            f"**Last Updated:** {data.get('engine_update', 'N/A')}")

    else:
        st.success("### ✅ No threats detected",
                   help="This file was not marked as malicious or suspicious by any engine")

    # Add custom CSS styling
    st.markdown("""
    <style>
        .stMetric {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 15px;
            background: white;
        }
        .stMetric label {
            font-size: 1.1rem !important;
            font-weight: 500 !important;
            color: #2c3e50 !important;
        }
        .stMetric div:first-child {
            color: #7f8c8d !important;
        }
    </style>
    """, unsafe_allow_html=True)


def main():
    st.header("🔰 SecureCode - Security Testing Tool", divider='green')

    if not st.session_state['logged_in']:
        with st.container(border=True):
            tab1, tab2 = st.tabs(["Login", "Register"])
            with tab1:
                user_controller.login()
            with tab2:
                user_controller.register()
    else:
        user_id = st.session_state['user_id']

        with st.sidebar:
            st.success(f"Welcome {st.session_state['user']}")
            option = option_menu("Main Menu", ["Home", "Recent Codes", "Logout"],
                                 icons=['house', 'clock', 'door-open'],
                                 menu_icon="cast", default_index=0)
            if option == "Logout":
                st.session_state.clear()
                st.rerun()

        if option == "Recent Codes":
            load_css()
            with st.container(border=True):
                show_recent_codes_on_main(user_id)

        if option == "Home":
            load_css()
            with st.container(border=True):
                st.header("Security Scan Options")
                st.session_state['scan_type'] = st.radio(
                    "Select Scan Type:",
                    ("Check Vulnerability", "Check Malware"),
                    horizontal=True
                )

                if st.session_state['scan_type'] == "Check Vulnerability":
                    st.header("Paste your Python code below:")
                    title = st.text_input(
                        "Enter a title for your code submission")
                    user_code = st_ace(language='python',
                                       theme='monokai', key="user_code")

                    if title and not is_unique_title(user_id, title):
                        st.error(
                            "Title already exists. Choose a different one.")

                    if st.button("Check Vulnerabilities") and title and user_code:
                        if not is_unique_title(user_id, title):
                            st.error(
                                "Title already exists. Choose a different one.")
                        else:
                            with st.spinner('Scanning...'):
                                st.session_state.update({
                                    'last_user_code': user_code,
                                    'vulnerability_report': user_controller.scan_vulnerabilities(user_code),
                                    'scan_complete': True,
                                    'issue_resolved': False
                                })
                                user_model.save_code(
                                    user_id, title, user_code, None)

                    if st.session_state['vulnerability_report']:
                        st.write("### Vulnerability Report")
                        st.text(st.session_state['vulnerability_report'])

                        issues = parse_vulnerabilities(
                            st.session_state['vulnerability_report'])
                        for i, issue in enumerate(issues):
                            key = f"issue_{i}"
                            st.session_state['selected_issues'][key] = st.checkbox(
                                issue, value=st.session_state['selected_issues'].get(
                                    key, False),
                                key=key, on_change=update_issues_selected
                            )

                    if st.session_state.get('show_resolve_button', False):
                        if st.button("Resolve Selected Issues with OpenAI"):
                            with st.spinner('Fixing code...'):
                                selected_issues = "\n".join(
                                    issue for i, issue in enumerate(issues)
                                    if st.session_state['selected_issues'][f"issue_{i}"]
                                )
                                st.session_state['fixed_code'] = rewrite_code_with_openai(
                                    st.session_state['last_user_code'], selected_issues)
                                st.session_state['issue_resolved'] = True
                                user_model.save_code(user_id, title,
                                                     st.session_state['last_user_code'],
                                                     st.session_state['fixed_code'])

                    if st.session_state['issue_resolved']:
                        VulnerabilityFreeCode(
                            st.session_state['fixed_code'],
                            st.session_state['vulnerability_report'],
                            report_service
                        ).display()

                # In the malware check section
                else:  # Malware Check Section
                    st.header("File Malware Analysis")
                    uploaded_file = st.file_uploader(
                        "Upload file for scanning",
                        type=["exe", "dll", "pdf", "docx",
                              "xlsx", "py", "js", "zip"],
                        accept_multiple_files=False
                    )

                    if st.button("Analyze with SecureCode"):
                        if uploaded_file is not None:
                            # Store file content in session state
                            st.session_state['uploaded_file_content'] = uploaded_file.getvalue(
                            )
                            with st.spinner('Scanning file...'):
                                try:
                                    st.session_state['malware_result'] = malware_service.scan_file(
                                        st.session_state['uploaded_file_content'],
                                        uploaded_file.name
                                    )
                                except Exception as e:
                                    st.error(f"Scan failed: {str(e)}")
                                    st.session_state['malware_result'] = None
                        else:
                            st.warning("Please upload a file first")

                    if st.session_state['malware_result']:
                        # Pass file content to display function
                        display_malware_result(
                            st.session_state['malware_result'],
                            st.session_state.get('uploaded_file_content', b'')
                        )


if __name__ == "__main__":
    user_model.create_tables()
    main()
