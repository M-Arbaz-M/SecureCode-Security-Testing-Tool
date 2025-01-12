import os
import openai
import streamlit as st
from streamlit_ace import st_ace
from dotenv import load_dotenv
from user_controller import UserController
from vulnerability_service import VulnerabilityService
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

# Initialize session state variables if not already set
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
    'scan_complete': False
}
for key, value in session_vars.items():
    if key not in st.session_state:
        st.session_state[key] = value

user_model = UserModel()
vulnerability_service = VulnerabilityService()
user_controller = UserController(user_model, vulnerability_service)
report_service = ReportService()


def parse_vulnerabilities(vulnerability_report):
    """Parse individual issues from the vulnerability report based on specific patterns."""
    issues = re.findall(
        r'>> Issue: (.*?)\n\s+Severity: (.*?)\s+Confidence: (.*?)\n\s+Location: (.*?)\n', vulnerability_report, re.DOTALL)
    parsed_issues = [
        f"Issue: {desc}\nSeverity: {sev} | Confidence: {conf} | Location: {loc}" for desc, sev, conf, loc in issues]
    return parsed_issues


def update_issues_selected():
    """Update issues_selected flag based on selected issues."""
    st.session_state['issues_selected'] = any(
        st.session_state['selected_issues'].values())
    # Ensure button visibility
    st.session_state['show_resolve_button'] = st.session_state['issues_selected']


def show_recent_codes_on_main(user_id):
    """Display recent code submissions with search and date filters."""

    with st.container(border=True):
        st.subheader("Recent Code Submissions")

        col1, col2, col3 = st.columns([0.5, 0.25, 0.25])
        with col1:
            search_query = st.text_input("Search by title or code content")

        with col2:
            start_date = st.date_input("Start Date", value=None)
        with col3:
            end_date = st.date_input("End Date", value=None)

    with st.container(border=True):

        if start_date:
            start_date = datetime.combine(start_date, datetime.min.time())
        if end_date:
            end_date = datetime.combine(end_date, datetime.max.time())

        recent_codes = user_model.get_recent_codes(user_id)
        if not recent_codes:
            st.write("No recent submissions.")
            return

    today, yesterday = datetime.now().date(), datetime.now().date() - timedelta(days=1)
    last_7_days, last_30_days = today - \
        timedelta(days=7), today - timedelta(days=30)

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

        if (not search_query or search_query.lower() in title.lower() or search_query.lower() in input_code.lower()) and \
           ((not start_date or submission_date >= start_date.date()) and (not end_date or submission_date <= end_date.date())):

            if submission_date == today:
                grouped_codes["Today"].append(
                    (title, input_code, output_code, created_at))
            elif submission_date == yesterday:
                grouped_codes["Yesterday"].append(
                    (title, input_code, output_code, created_at))
            elif last_7_days <= submission_date < today:
                grouped_codes["Previous 7 Days"].append(
                    (title, input_code, output_code, created_at))
            elif last_30_days <= submission_date < last_7_days:
                grouped_codes["Previous 30 Days"].append(
                    (title, input_code, output_code, created_at))
            else:
                grouped_codes["Older"].append(
                    (title, input_code, output_code, created_at))

    for group, codes in grouped_codes.items():
        if codes:
            st.subheader(group)
            for i, (title, input_code, output_code, created_at) in enumerate(codes, start=1):
                with st.expander(f"{title} on {created_at.strftime('%Y-%m-%d')}"):
                    st.write("**Input Code:**")
                    st.code(input_code, language="python")
                    st.write("**Output Code:**")
                    st.write(output_code)


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
            option = option_menu("Main Menu", ["Home", "Recent Codes", "Logout"], icons=[
                                 'house', 'clock', 'door-open'], menu_icon="cast", default_index=0)

            if option == "Logout":
                st.session_state['logged_in'] = False
                st.session_state['user'] = None
                st.session_state['user_id'] = None
                st.rerun()

        if option == "Recent Codes":
            load_css()
            with st.container(border=True):
                show_recent_codes_on_main(user_id)

        if option == "Home":
            load_css()
            with st.container(border=True):
                st.header("Paste your Python code below:")

                title = st.text_input("Enter a title for your code submission")
                user_code = st_ace(language='python',
                                   theme='monokai', key="user_code")

                # Check if the vulnerability scan should be performed
                if st.button("Check Vulnerabilities") or st.session_state['scan_complete'] is False:
                    # Reset only if the user explicitly triggers a new scan
                    if user_code and title:
                        # Clear previous report
                        st.session_state['vulnerability_report'] = ""
                        # Reset selected issues
                        st.session_state['selected_issues'] = {}
                        # Reset scan status
                        st.session_state['scan_complete'] = False

                        with st.spinner('Checking vulnerabilities...'):
                            st.session_state['last_user_code'] = user_code
                            result = user_controller.scan_vulnerabilities(
                                user_code)
                            st.session_state['vulnerability_report'] = result
                            st.session_state['scan_complete'] = True
                            st.session_state['issue_resolved'] = False

                            user_id = st.session_state.get('user_id')
                            if user_id:
                                user_model.save_code(
                                    user_id, title, st.session_state['last_user_code'], None)

                # Display vulnerability report if available
                if st.session_state['vulnerability_report']:
                    st.write("**Vulnerability Report:**")
                    st.text(st.session_state['vulnerability_report'])

                    # Parse and display issues with checkboxes
                    issues = parse_vulnerabilities(
                        st.session_state['vulnerability_report'])
                    for i, issue in enumerate(issues):
                        checkbox_key = f"issue_{i}"
                        if checkbox_key not in st.session_state['selected_issues']:
                            st.session_state['selected_issues'][checkbox_key] = False

                        # Checkbox for each issue
                        st.session_state['selected_issues'][checkbox_key] = st.checkbox(
                            issue, value=st.session_state['selected_issues'][checkbox_key],
                            key=checkbox_key, on_change=update_issues_selected
                        )

            # Display the resolve button based on issues selected
            if st.session_state.get('show_resolve_button', False) and st.session_state['issues_selected']:
                if st.button("Resolve Selected Issues with OpenAI"):
                    selected_issues_text = "\n".join(
                        issue for i, issue in enumerate(parse_vulnerabilities(st.session_state['vulnerability_report']))
                        if st.session_state['selected_issues'][f"issue_{i}"]
                    )

                    with st.spinner('Resolving selected vulnerabilities...'):
                        fixed_code = rewrite_code_with_openai(
                            st.session_state['last_user_code'], selected_issues_text)
                        st.session_state['fixed_code'] = fixed_code
                        st.session_state['issue_resolved'] = True

                        user_id = st.session_state.get('user_id')
                        if user_id:
                            user_model.save_code(
                                user_id, title, st.session_state['last_user_code'], st.session_state['fixed_code'])

            if st.session_state['issue_resolved']:
                vulnerability_free_code = VulnerabilityFreeCode(
                    st.session_state['fixed_code'],
                    st.session_state['vulnerability_report'],
                    report_service
                )
                vulnerability_free_code.display()


if __name__ == "__main__":
    user_model.create_tables()
    main()
