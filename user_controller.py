import psycopg2.errors 
import streamlit as st

class UserController:

    def load_css():
        with open('static/style.css') as f:
            css_code = f.read()
        st.markdown(f'<style>{css_code}</style>', unsafe_allow_html=True)

    def __init__(self, user_model, vulnerability_service):
        self.user_model = user_model
        self.vulnerability_service = vulnerability_service

    def login(self):
        if "login_disabled" not in st.session_state:
            st.session_state["login_disabled"] = False

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        login_button = st.button("Login", disabled=st.session_state["login_disabled"])

        if login_button:
            st.session_state["login_disabled"] = True
            user = self.user_model.get_user(username, password)
            if user:
                st.session_state['logged_in'] = True
                st.session_state['user'] = username
                st.session_state['user_id'] = user[0]
                st.rerun()  
            else:
                st.error("Invalid login credentials.")
                st.session_state["login_disabled"] = False

    def register(self):
        if "register_disabled" not in st.session_state:
            st.session_state["register_disabled"] = False
    
        st.subheader("Register")
        username = st.text_input("Choose a Username")
        password = st.text_input("Choose a Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        register_button = st.button("Register", disabled=st.session_state["register_disabled"])
    
        if password == confirm_password:
            if register_button:
                st.session_state["register_disabled"] = True
                try:
                    self.user_model.add_user(username, password)
                    st.success("Registration successful! Please log in.")
                    st.rerun()
                except psycopg2.errors.UniqueViolation:
                    st.error("Username already exists. Please choose another one.")
                    st.session_state["register_disabled"] = False
                except Exception as e:
                    st.error(f"An error occurred: {str(e)}")
                    st.session_state["register_disabled"] = False
        else:
            st.error("Passwords do not match.")


    def scan_vulnerabilities(self, user_code):
        """
        This method interacts with the VulnerabilityService to scan the provided user code.
        """
        return self.vulnerability_service.detect_vulnerabilities(user_code)