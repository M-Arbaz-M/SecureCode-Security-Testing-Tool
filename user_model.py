import streamlit as st
from supabase import create_client
import psycopg2
from psycopg2 import OperationalError
import os

# Supabase credentials
url = st.secrets["URL"]
key = st.secrets["KEY"]

# Create a Supabase client (if needed for REST API interactions)
supabase = create_client(url, key)

# Load environment variables
db_host = st.secrets["DB_Host"]
db_database = st.secrets["DB_Database"]
db_user = st.secrets["DB_User"]
db_password = st.secrets["DB_Password"]


class UserModel:

    def get_db_connection(self):
        """Establish connection to Supabase PostgreSQL"""
        try:
            conn = psycopg2.connect(
                host=db_host,
                database=db_database,
                user=db_user,
                password=db_password,
                port=5432
            )
            return conn
        except OperationalError as e:
            st.error(f"Database connection error: {e}")
            raise

    def create_tables(self):
        """Create necessary tables in the database"""
        try:
            conn = self.get_db_connection()
            cur = conn.cursor()

            # Create users table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT
                );
            ''')

            # Create codes table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS codes (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    title TEXT,
                    input_code TEXT,
                    output_code TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            ''')

            conn.commit()
            cur.close()
            conn.close()
            st.success("")
        except Exception as e:
            st.error(f"Error creating tables: {e}")

    def add_user(self, username, password):
        conn = self.get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
        conn.commit()
        cur.close()
        conn.close()

    def get_user(self, username, password):
        conn = self.get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        user = cur.fetchone()
        cur.close()
        conn.close()
        return user

    def save_code(self, user_id, title, input_code, output_code):
        conn = self.get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                "INSERT INTO codes (user_id, title, input_code, output_code) VALUES (%s, %s, %s, %s)",
                (user_id, title, input_code, output_code)
            )
            conn.commit()

        except Exception as e:
            st.error(f"Error saving code: {e}")
        finally:
            cur.close()
            conn.close()

    def get_recent_codes(self, user_id):
        conn = self.get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                "SELECT title, input_code, output_code, created_at FROM codes WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
            codes = cur.fetchall()
            return codes
        except Exception as e:
            st.error(f"Error fetching recent codes: {e}")
            return []
        finally:
            cur.close()
            conn.close()
