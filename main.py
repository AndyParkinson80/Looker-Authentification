import os
import json
import pandas as pd
import time
import google.auth
from google.oauth2 import service_account
from google.cloud import resourcemanager_v3, secretmanager, bigquery
from google.iam.v1 import policy_pb2
from googleapiclient.discovery import build
from google.auth import exceptions as google_auth_exceptions
from google.oauth2 import service_account

data_export = False

def google_auth():
    """
    Authenticate using a service account.
    Supports GOOGLE_CLOUD_SECRET env var, GCP JSON file path in env var 'GCP',
    or Application Default Credentials (ADC) for local/GCP environments.
    Adds proper scopes for both Cloud APIs and Sheets API.
    """
    SCOPES = [
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/spreadsheets.readonly"
    ]

    secret_json = os.getenv("GOOGLE_CLOUD_SECRET")
    file_path = os.getenv("GCP")

    # 1. Auth from env var JSON
    if secret_json:
        service_account_info = json.loads(secret_json)
        credentials = service_account.Credentials.from_service_account_info(
            service_account_info,
            scopes=SCOPES
        )
        project_id = service_account_info.get("project_id")
        print("✅ Authenticated with service account from env var")
        return credentials, project_id

    # 2. Auth from file path
    elif file_path and os.path.exists(file_path):
        credentials = service_account.Credentials.from_service_account_file(
            file_path,
            scopes=SCOPES
        )
        with open(file_path) as f:
            project_id = json.load(f).get("project_id")

        print("✅ Authenticated with service account from file")
        return credentials, project_id

    # 3. Try Application Default Credentials (ADC)
    try:
        credentials, project_id = google.auth.default(scopes=SCOPES)
        print("✅ Authenticated using Application Default Credentials (ADC)")
        return credentials, project_id
    except google.auth.exceptions.DefaultCredentialsError:
        pass

    # 4. No valid auth found
    raise Exception("❌ No valid authentication method found")

def get_secret(secret_id, version_id="latest"):
    client = secretmanager.SecretManagerServiceClient(credentials=credentials)
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")

def read_emails_from_sheet(credentials, spreadsheet_id, sheet_name="Sheet1", email_column="email"):
    service = build('sheets', 'v4', credentials=credentials)
    sheet = service.spreadsheets()

    result = sheet.values().get(spreadsheetId=spreadsheet_id, range=sheet_name).execute()
    values = result.get('values', [])

    if not values or len(values) < 2:
        raise ValueError("Google Sheet is empty or missing data!")

    df = pd.DataFrame(values[1:], columns=values[0])
    if email_column not in df.columns:
        raise ValueError(f"Column '{email_column}' not found in Sheet.")
    
    emails = { e.strip() for e in df[email_column].dropna() if isinstance(e, str) and e.strip() != "" }
    return emails

def format_member(email):
    """
    Format member string with appropriate IAM prefix.
    """
    email = email.strip()
    
    # Already has a prefix
    if ':' in email and email.split(':')[0] in ['user', 'serviceAccount', 'group', 'domain']:
        return email
    
    # Service account
    if email.endswith('.gserviceaccount.com') or email.endswith('.iam.gserviceaccount.com'):
        return f"serviceAccount:{email}"
    
    # Group
    if email.startswith('group@') or '@googlegroups.com' in email:
        return f"group:{email}"
    
    # Default to user
    return f"user:{email}"

def extract_email(member):
    """
    Extract email from IAM member string (removes prefix like 'user:', 'serviceAccount:', etc.)
    """
    if ':' in member:
        return member.split(':', 1)[1]
    return member

def sync_bigquery_roles_from_sheet(credentials, project_id, spreadsheet_id, sheet_name="Sheet1", email_column="email"):
    target_roles = [
        "roles/bigquery.dataViewer",
        "roles/bigquery.jobUser",
    ]

    client = resourcemanager_v3.ProjectsClient(credentials=credentials)
    resource = f"projects/{project_id}"

    # Load emails from Google Sheet
    sheet_emails = read_emails_from_sheet(credentials, spreadsheet_id, sheet_name, email_column)
    print(f"🔹 Found {len(sheet_emails)} emails in Google Sheet")

    # Get current IAM policy
    policy = client.get_iam_policy(request={"resource": resource})

    # Map role -> set of members
    role_to_members = {role: set() for role in target_roles}
    other_bindings = []

    for binding in policy.bindings:
        if binding.role in target_roles:
            role_to_members[binding.role].update(binding.members)
        else:
            other_bindings.append(binding)  # keep other roles intact

    # Remove USER members not in the Sheet (keep service accounts and other types)
    for role, members in role_to_members.items():
        members_to_remove = set()
        for m in members:
            # Only remove user: members that aren't in the sheet
            if m.startswith("user:"):
                email = extract_email(m)
                if email not in sheet_emails:
                    members_to_remove.add(m)
                    print(f"➖ Removing {m} from {role} (not in Sheet)")
        
        members -= members_to_remove

    # Add members from the Sheet
    for email in sheet_emails:
        member = format_member(email)
        for role in target_roles:
            if member not in role_to_members[role]:
                role_to_members[role].add(member)
                print(f"➕ Adding {member} to {role}")

    # Rebuild IAM bindings
    updated_bindings = []
    for role, members in role_to_members.items():
        if members:
            updated_bindings.append(policy_pb2.Binding(
                role=role,
                members=list(members)
            ))
    updated_bindings.extend(other_bindings)

    # Update IAM policy
    new_policy = policy_pb2.Policy(bindings=updated_bindings, etag=policy.etag)
    client.set_iam_policy(request={"resource": resource, "policy": new_policy})
    print("✅ IAM policy synced successfully.")

def generate_rls_sql_from_sheet(
    credentials,
    spreadsheet_id,
    sheet_name,
    email_column,
    rls_policy_tag,
    rls_policy_tag_value,
    rls_table,
    rls_filename,
    ):

    service = build("sheets", "v4", credentials=credentials)
    sheet = service.spreadsheets()

    result = sheet.values().get(
        spreadsheetId=spreadsheet_id,
        range=sheet_name
    ).execute()

    values = result.get("values", [])
    if not values or len(values) < 2:
        raise ValueError("Google Sheet is empty or missing data!")

    df = pd.DataFrame(values[1:], columns=values[0])

    # validate required columns
    for col in [email_column, rls_policy_tag, rls_policy_tag_value]:
        if col not in df.columns:
            raise ValueError(f"Required column '{col}' missing from Sheet")

    grouped = {}

    for _, row in df.iterrows():
        tag_value = str(row[rls_policy_tag]).strip()
        email = str(row[email_column]).strip()
        filter_value = str(row[rls_policy_tag_value]).strip()

        # ignore blank tags
        if tag_value == "" or tag_value.lower() in ["nan", "none"]:
            continue

        if tag_value not in grouped:
            grouped[tag_value] = {
                "emails": set(),
                "filter": filter_value
            }

        if email:
            grouped[tag_value]["emails"].add(email)

    sql_statements = []

    # Add DROP statement at the beginning
    drop_statement = f"DROP ALL ROW ACCESS POLICIES ON {rls_table};\n"
    sql_statements.append(drop_statement)

    for tag_value, data in grouped.items():
        policy_name = f"absences_{tag_value}"

        principals = []
        for email in sorted(data["emails"]):
            principals.append(f"\"{format_member(email)}\"")

        principals_str = ",\n    ".join(principals)

        stmt = f"""CREATE OR REPLACE ROW ACCESS POLICY {policy_name}
    ON {rls_table}
    GRANT TO (
        {principals_str}
    )
    FILTER USING ({data["filter"]});
    """
        sql_statements.append(stmt)

    full_sql = "\n".join(sql_statements)

    if data_export:
        if rls_filename:
            with open(rls_filename, "w", encoding="utf-8") as f:
                f.write(full_sql)
            print(f"📄 RLS SQL written to {rls_filename}")
    else:
        print(f"📄 RLS SQL generated for {rls_filename} (not exported)")

    return full_sql

def execute_rls_sql(credentials, project_id, sql_content, policy_name):
    client = bigquery.Client(credentials=credentials, project=project_id)
    
    # Split SQL into statements
    statements = [s.strip() for s in sql_content.split(';') if s.strip()]
    num_statements = len(statements)
    print(f"⏳ About to execute {num_statements} SQL statements for policy '{policy_name}'...")

    start_time = time.perf_counter()
    
    try:
        for statement in statements:
            query_job = client.query(statement)
            query_job.result()  # Wait for completion

        end_time = time.perf_counter()
        elapsed = end_time - start_time
        print(f"✅ Finished executing {num_statements} statements for '{policy_name}' in {elapsed:.2f} seconds")
    
    except Exception as e:
        end_time = time.perf_counter()
        elapsed = end_time - start_time
        print(f"❌ Error executing '{policy_name}' after {elapsed:.2f} seconds: {str(e)}")
        raise

if __name__ == "__main__":
    credentials, project_id = google_auth()
    SHEET_ID = get_secret('looker_dashboard_sheet_id')

    sync_bigquery_roles_from_sheet(
        credentials,
        project_id,
        SHEET_ID,
        sheet_name="Data Access",
        email_column="emails"
    )

    rls_configs = [
        ("absence_", "absence_tag_value", "absence_dashboard.absences", "rls_absences"),
        ("leavers_", "leavers_tag_value", "leavers_dashboard.staff_data", "rls_leavers"),
        ("recruitment_", "recruitment_tag_value", "usa_recruitment_dashboard.main", "rls_usa_recruitment"),
        ("Imperago_Audits_", "Imperago_Audit_tag_value", "Imperago_downloads.Joined", "rls_imperago_audit"),
    ]

    for prefix, tag_column, table, policy_name in rls_configs:
        sql_content = generate_rls_sql_from_sheet(
            credentials, SHEET_ID, "Data Access", "emails",
            prefix, tag_column, table, policy_name
        )

        execute_rls_sql(credentials, project_id, sql_content, policy_name)
