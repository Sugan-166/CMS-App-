import streamlit as st
import pandas as pd
import random
import string
import time
import hashlib  # For password hashing
from datetime import datetime  # For timestamps
import matplotlib.pyplot as plt  # For analytics
import os  # For file uploads
import io

# Define backend API URL
BASE_URL = "http://127.0.0.1:5000"  # Change this if needed

# Set page config with a new icon (🚨)
st.set_page_config(page_title="Student Complaint Management System", layout="wide", page_icon="🚨")
st.title("🎓 Student Complaint Management System")

# --- Initialize Session State ---
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
    st.session_state["user_id"] = None
    st.session_state["role"] = None
    st.session_state["admin_type"] = None
if "complaints" not in st.session_state:
    st.session_state["complaints"] = []
if "users" not in st.session_state:
    st.session_state["users"] = []  # Simulate a user database

# --- Password Hashing ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- Generate Random Complaint ID ---
def generate_complaint_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

# --- User Registration ---
def user_registration():
    st.subheader("👤 User Registration")
    name = st.text_input("Full Name")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    role = st.selectbox("Role", ["Student", "Admin"])

    if st.button("Register"):
        if not name or not email or not password or not confirm_password:
            st.error("⚠️ All fields are required!")
        elif password != confirm_password:
            st.error("⚠️ Passwords do not match!")
        else:
            # Check if user already exists
            if any(user["email"] == email for user in st.session_state["users"]):
                st.error("❌ User with this email already exists!")
            else:
                # Add user to the database
                new_user = {
                    "user_id": f"USER_{len(st.session_state['users']) + 1}",
                    "name": name,
                    "email": email,
                    "password": hash_password(password),
                    "role": role.lower(),
                    "admin_type": None if role.lower() == "student" else "Hostel"  # Default admin type
                }
                st.session_state["users"].append(new_user)
                st.success("✅ Registration successful! Please login.")

# --- Student Login ---
def student_login():
    st.subheader("👨‍🎓 Student Login")
    email = st.text_input("Email", key="student_email")
    password = st.text_input("Password", type="password", key="student_password")

    if st.button("Login"):
        user = next((user for user in st.session_state["users"] if user["email"] == email and user["role"] == "student"), None)
        if user and user["password"] == hash_password(password):
            st.session_state["logged_in"] = True
            st.session_state["user_id"] = user["user_id"]
            st.session_state["role"] = "student"
            st.success("✅ Student login successful!")
            time.sleep(1)
            st.rerun()
        else:
            st.error("❌ Invalid credentials")

# --- Admin Login ---
def admin_login():
    st.subheader("🛠 Admin Login")
    email = st.text_input("Email", key="admin_email")
    password = st.text_input("Password", type="password", key="admin_password")
    selected_admin_type = st.selectbox("Select Admin Type", [
        "Hostel", "Mess", "Academics", "Transportation", "Infrastructure",
        "Administration", "Discipline & Security", "Sports & Extra-curricular",
        "Technical Issues", "Others"
    ], key="admin_type_select")

    if st.button("Login as Admin"):
        user = next((user for user in st.session_state["users"] if user["email"] == email and user["role"] == "admin"), None)
        if user and user["password"] == hash_password(password):
            st.session_state["logged_in"] = True
            st.session_state["user_id"] = user["user_id"]
            st.session_state["role"] = "admin"
            st.session_state["admin_type"] = selected_admin_type
            st.success(f"✅ Admin login successful! Category: {selected_admin_type}")
            time.sleep(1)
            st.rerun()
        else:
            st.error("❌ Invalid credentials")

# --- Submit Complaint (Student) ---
def submit_complaint():
    st.subheader("📩 Submit a Complaint")
    title = st.text_input("Complaint Title")
    description = st.text_area("Describe your complaint")
    category = st.selectbox("Category", [
        "Hostel", "Mess", "Academics", "Transportation", "Infrastructure",
        "Administration", "Discipline & Security", "Sports & Extra-curricular",
        "Technical Issues", "Others"
    ])
    urgency = st.selectbox("Urgency Level", ["Low", "Medium", "High"], key="urgency_level")
    uploaded_file = st.file_uploader("Attach File (Optional)", type=["pdf", "jpg", "png"])

    if st.button("Submit Complaint"):
        if not title or not description:
            st.error("⚠️ Title and Description cannot be empty!")
            return

        complaint_id = generate_complaint_id()

        # Save uploaded file
        file_path = None  # Initialize file_path to None
        if uploaded_file:
            file_path = f"uploads/{complaint_id}_{uploaded_file.name}"
            os.makedirs("uploads", exist_ok=True)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

        # Create the complaint dictionary with file_path always present
        new_complaint = {
            "complaint_id": complaint_id,
            "student_id": st.session_state["user_id"],
            "title": title,
            "description": description,
            "category": category,
            "urgency": urgency,
            "status": "Pending",
            "file_path": file_path,  # This will be None if no file is uploaded
            "admin_response": None,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        st.session_state["complaints"].append(new_complaint)
        st.success(f"✅ Complaint submitted successfully!\n\n🆔 **Complaint ID:** `{complaint_id}`\n📂 **Category:** `{category}`\n⚠️ **Urgency:** `{urgency}`")
        time.sleep(1)
        st.rerun()

# --- View Complaint Status (Student) ---
def view_complaint_status():
    st.subheader("📄 Your Complaint Status")

    student_id = st.session_state.get("user_id")
    if not student_id:
        st.error("❌ Error: Student ID is missing")
        return

    complaints = [c for c in st.session_state["complaints"] if c["student_id"] == student_id]

    if not complaints:
        st.warning("No complaints found for your account.")
        return

    for complaint in complaints:
        st.markdown(f"### 📌 Complaint ID: `{complaint['complaint_id']}`")
        st.write(f"**📝 Title:** {complaint['title']}")
        st.write(f"**📜 Description:** {complaint['description']}")
        st.write(f"**📂 Category:** {complaint['category']}")
        st.write(f"**⚠️ Urgency:** {complaint['urgency']}")
        st.write(f"**🔴 Status:** {complaint['status']}")
        if complaint["admin_response"]:
            st.write(f"**📩 Admin Response:** {complaint['admin_response']}")
        if complaint["file_path"]:
            st.write(f"**📎 Attached File:** [Download]({complaint['file_path']})")
        st.markdown("---")

# --- View Complaints (Admin) ---
def view_complaints_admin():
    st.subheader(f"📋 Complaints for {st.session_state['admin_type']} Admin")

    # Filter complaints based on the admin's category
    admin_category = st.session_state["admin_type"]
    filtered_complaints = [c for c in st.session_state["complaints"] if c["category"] == admin_category]

    if not filtered_complaints:
        st.warning(f"No complaints found for {admin_category} category.")
        return

    # Search and Filter Functionality
    search_query = st.text_input("Search by Complaint ID or Title")
    if search_query:
        filtered_complaints = [c for c in filtered_complaints if search_query.lower() in c["complaint_id"].lower() or search_query.lower() in c["title"].lower()]

    for complaint in filtered_complaints:
        st.markdown(f"### 📌 Complaint ID: `{complaint['complaint_id']}`")
        st.write(f"**📝 Title:** {complaint['title']}")
        st.write(f"**📜 Description:** {complaint['description']}")
        st.write(f"**📂 Category:** {complaint['category']}")
        st.write(f"**⚠️ Urgency:** {complaint['urgency']}")

        # Status Update Section
        current_status = complaint["status"]
        new_status = st.selectbox(
            f"Update Status for {complaint['complaint_id']}",
            ["Pending", "In Progress", "Resolved"],
            index=["Pending", "In Progress", "Resolved"].index(current_status),
            key=f"status_{complaint['complaint_id']}"
        )

        if st.button(f"Update Status for {complaint['complaint_id']}"):
            complaint["status"] = new_status
            st.success(f"Status updated to **{new_status}** for Complaint ID: {complaint['complaint_id']}")
            time.sleep(1)
            st.rerun()

        st.write(f"**🔴 Status:** {complaint['status']}")

        if complaint.get("file_path"):  # Use .get() to safely access the key
            st.write(f"**📎 Attached File:** [Download]({complaint['file_path']})")
        else:
            st.write("**📎 Attached File:** None")  # Handle case where no file is attached

        # Admin Response System
        admin_response = st.text_area(f"Response to {complaint['complaint_id']}", key=f"response_{complaint['complaint_id']}")
        if st.button(f"Submit Response for {complaint['complaint_id']}"):
            complaint["admin_response"] = admin_response
            st.success(f"Response submitted for Complaint ID: {complaint['complaint_id']}")
            time.sleep(1)
            st.rerun()

        st.markdown("---")

# --- Analytics Dashboard ---
def analytics_dashboard():
    st.subheader("📊 Analytics Dashboard")

    if not st.session_state["complaints"]:
        st.warning("No complaints found for analysis.")
        return

    # Convert complaints to DataFrame
    df = pd.DataFrame(st.session_state["complaints"])

    # Complaints by Category
    st.write("### Complaints by Category")
    category_counts = df["category"].value_counts()
    st.bar_chart(category_counts)

    # Complaints by Status
    st.write("### Complaints by Status")
    status_counts = df["status"].value_counts()
    st.bar_chart(status_counts)

    # Complaints by Urgency
    st.write("### Complaints by Urgency")
    urgency_counts = df["urgency"].value_counts()
    st.bar_chart(urgency_counts)

# --- Logout ---
def logout():
    st.session_state["logged_in"] = False
    st.session_state["user_id"] = None
    st.session_state["role"] = None
    st.session_state["admin_type"] = None
    st.success("Logged out successfully ✅")
    time.sleep(1)
    st.rerun()

# --- Export Complaints ---
def export_complaints():
    st.subheader("📤 Export Complaints")

    # Check if there are any complaints to export
    if not st.session_state["complaints"]:
        st.warning("No complaints available to export.")
        return

    # Convert complaints to a DataFrame
    complaints_df = pd.DataFrame(st.session_state["complaints"])

    # Allow the user to select which complaints to export
    if st.session_state["role"] == "student":
        # Students can only export their own complaints
        student_id = st.session_state["user_id"]
        complaints_df = complaints_df[complaints_df["student_id"] == student_id]
    elif st.session_state["role"] == "admin":
        # Admins can export complaints based on their category
        admin_category = st.session_state["admin_type"]
        complaints_df = complaints_df[complaints_df["category"] == admin_category]

    # Check if there are any complaints after filtering
    if complaints_df.empty:
        st.warning("No complaints match your criteria for export.")
        return

    # Display the complaints to be exported
    st.write("### Complaints to Export")
    st.dataframe(complaints_df)

    # Export options
    export_format = st.selectbox("Select export format", ["CSV", "Excel"])

    if st.button("Export Complaints"):
        if export_format == "CSV":
            # Export to CSV
            csv_file = complaints_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="Download CSV",
                data=csv_file,
                file_name="complaints_export.csv",
                mime="text/csv",
            )
        elif export_format == "Excel":
            # Export to Excel
            output = io.BytesIO()  # Create a BytesIO object
            with pd.ExcelWriter(output, engine="openpyxl") as writer:
                complaints_df.to_excel(writer, index=False)
            excel_file = output.getvalue()  # Get the value of the BytesIO object
            st.download_button(
                label="Download Excel",
                data=excel_file,
                file_name="complaints_export.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        st.success("Complaints exported successfully!")

# --- Sidebar Navigation ---
menu = st.sidebar.radio("🔍 Navigation", ["User Registration", "Student Login", "Admin Login", "Logout"])

if not st.session_state["logged_in"]:
    if menu == "User Registration":
        user_registration()
    elif menu == "Student Login":
        student_login()
    elif menu == "Admin Login":
        admin_login()
else:
    st.sidebar.success(f"Logged in as *{st.session_state['role'].capitalize()}*")

    if st.session_state["role"] == "student":
        # Student options
        sub_menu = st.sidebar.radio("Student Options", ["Submit Complaint", "View Complaint Status", "Logout"])
        if sub_menu == "Submit Complaint":
            submit_complaint()
        elif sub_menu == "View Complaint Status":
            view_complaint_status()
        elif sub_menu == "Logout":
            logout()

    elif st.session_state["role"] == "admin":
        # Admin options
        sub_menu = st.sidebar.radio("Admin Options", ["View Complaints", "Analytics Dashboard", "Export Complaints", "Logout"])
        if sub_menu == "View Complaints":
            view_complaints_admin()
        elif sub_menu == "Analytics Dashboard":
            analytics_dashboard()
        elif sub_menu == "Export Complaints":
            export_complaints()
        elif sub_menu == "Logout":
            logout()
