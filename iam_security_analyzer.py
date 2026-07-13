#!/usr/bin/env python3
# IAM Security Analyzer
# Darp Kalavadia
#
# Scans an AWS account's IAM users/groups/roles and checks their policies
# for common misconfigurations - wildcard permissions, privilege escalation
# paths, and old access keys. Everything is read-only, no changes are made
# to the account.
#
# The privilege escalation checks are based on the well-known Rhino Security
# Labs research on IAM privesc methods.

import boto3
import json
import datetime
import pytz
from botocore.exceptions import ClientError
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

# actions that can be abused to escalate privileges if a user/role has them
PRIVESC_ACTIONS = {
    "iam:CreatePolicyVersion": "can create a new policy version with any permissions",
    "iam:SetDefaultPolicyVersion": "can switch back to an older, more permissive policy version",
    "iam:AttachUserPolicy": "can attach AdministratorAccess (or anything) to a user",
    "iam:AttachGroupPolicy": "can attach any managed policy to a group",
    "iam:AttachRolePolicy": "can attach any managed policy to a role",
    "iam:PutUserPolicy": "can add an inline policy with arbitrary permissions",
    "iam:PutGroupPolicy": "can add an inline policy to a group",
    "iam:PutRolePolicy": "can add an inline policy to a role",
    "iam:AddUserToGroup": "can move themselves/others into a more privileged group",
    "iam:UpdateAssumeRolePolicy": "can change trust policy to allow assuming privileged roles",
    "iam:CreateAccessKey": "can create keys for other users (impersonation)",
    "iam:CreateLoginProfile": "can set a console password for another user",
    "iam:UpdateLoginProfile": "can reset someone else's console password",
    "sts:AssumeRole": "can assume other roles - worth checking trust boundaries",
    "iam:PassRole": "risky if combined with ec2:RunInstances / lambda:CreateFunction etc",
}

ACCESS_KEY_MAX_AGE_DAYS = 90


def get_policy_document(iam_client, policy_arn):
    # managed policies need 2 calls - get the policy, then get its default version
    policy = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
    version_id = policy["DefaultVersionId"]
    version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    return version["PolicyVersion"]["Document"]


def collect_policy_documents(iam_client, identity_type, identity_name):
    # grabs both attached (managed) and inline policies for a user/group/role
    docs = []

    list_attached = {
        "user": iam_client.list_attached_user_policies,
        "group": iam_client.list_attached_group_policies,
        "role": iam_client.list_attached_role_policies,
    }[identity_type]
    kwarg_name = {"user": "UserName", "group": "GroupName", "role": "RoleName"}[identity_type]

    resp = list_attached(**{kwarg_name: identity_name})
    for p in resp.get("AttachedPolicies", []):
        try:
            doc = get_policy_document(iam_client, p["PolicyArn"])
            docs.append((p["PolicyName"], doc))
        except ClientError as e:
            print(f"  [!] couldn't read {p['PolicyName']}: {e}")

    list_inline = {
        "user": iam_client.list_user_policies,
        "group": iam_client.list_group_policies,
        "role": iam_client.list_role_policies,
    }[identity_type]
    get_inline = {
        "user": iam_client.get_user_policy,
        "group": iam_client.get_group_policy,
        "role": iam_client.get_role_policy,
    }[identity_type]

    for name in list_inline(**{kwarg_name: identity_name}).get("PolicyNames", []):
        doc = get_inline(**{kwarg_name: identity_name, "PolicyName": name})["PolicyDocument"]
        docs.append((name, doc))

    return docs


def as_list(x):
    # IAM policies let Action/Resource be either a string or a list, annoying
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def analyze_policy_document(policy_name, document, identity_type, identity_name):
    findings = []

    for stmt in as_list(document.get("Statement", [])):
        if stmt.get("Effect") != "Allow":
            continue

        actions = [a.lower() for a in as_list(stmt.get("Action", []))]
        resources = as_list(stmt.get("Resource", []))

        if "*" in actions:
            findings.append({
                "Severity": "Critical",
                "Resource": f"{identity_type}:{identity_name}",
                "Policy": policy_name,
                "Issue": "wildcard action (*) - grants literally everything",
            })

        if "*" in resources and "*" not in actions:
            action_str = ", ".join(as_list(stmt.get("Action", [])))[:120]
            findings.append({
                "Severity": "High",
                "Resource": f"{identity_type}:{identity_name}",
                "Policy": policy_name,
                "Issue": f"wildcard resource (*) applies to: {action_str}",
            })

        for action in as_list(stmt.get("Action", [])):
            if action in PRIVESC_ACTIONS:
                findings.append({
                    "Severity": "Critical",
                    "Resource": f"{identity_type}:{identity_name}",
                    "Policy": policy_name,
                    "Issue": f"privesc risk - {action}: {PRIVESC_ACTIONS[action]}",
                })

    return findings


def check_access_key_age(iam_client, user_name):
    # flags access keys that haven't been rotated in a while
    findings = []
    try:
        keys = iam_client.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    except ClientError:
        return findings

    now = datetime.datetime.now(datetime.timezone.utc)
    for key in keys:
        age = (now - key["CreateDate"]).days
        if age >= ACCESS_KEY_MAX_AGE_DAYS:
            findings.append({
                "Severity": "Medium",
                "Resource": f"user:{user_name}",
                "Policy": "-",
                "Issue": f"access key {key['AccessKeyId'][:10]}... is {age} days old, rotate it",
            })
    return findings


def scan_account(iam_client):
    all_findings = []

    print("[*] checking users...")
    for user in iam_client.list_users()["Users"]:
        name = user["UserName"]
        for policy_name, doc in collect_policy_documents(iam_client, "user", name):
            all_findings += analyze_policy_document(policy_name, doc, "user", name)
        all_findings += check_access_key_age(iam_client, name)

    print("[*] checking groups...")
    for group in iam_client.list_groups()["Groups"]:
        name = group["GroupName"]
        for policy_name, doc in collect_policy_documents(iam_client, "group", name):
            all_findings += analyze_policy_document(policy_name, doc, "group", name)

    print("[*] checking roles...")
    for role in iam_client.list_roles()["Roles"]:
        name = role["RoleName"]
        for policy_name, doc in collect_policy_documents(iam_client, "role", name):
            all_findings += analyze_policy_document(policy_name, doc, "role", name)

    return all_findings


def generate_reports(findings, account_id, region):
    if not findings:
        findings = [{"Severity": "None", "Resource": "-", "Policy": "-", "Issue": "no issues found"}]

    ist = pytz.timezone("Asia/Kolkata")
    time_str = datetime.datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S %Z")

    # json first, easiest
    with open("findings.json", "w") as f:
        json.dump(findings, f, indent=4)

    # html report
    rows = "".join(
        f"<tr><td>{f['Severity']}</td><td>{f['Resource']}</td><td>{f['Policy']}</td><td>{f['Issue']}</td></tr>"
        for f in findings
    )
    html = f"""<html><head><title>IAM Security Audit</title></head><body>
    <h1>AWS IAM Security Audit Report</h1>
    <p><b>Account:</b> {account_id}<br><b>Region:</b> {region}<br><b>Time:</b> {time_str}</p>
    <table border="1" cellspacing="0" cellpadding="5">
    <tr><th>Severity</th><th>Resource</th><th>Policy</th><th>Issue</th></tr>
    {rows}
    </table></body></html>"""
    with open("IAM_Report.html", "w", encoding="utf-8") as f:
        f.write(html)

    # pdf report - same data as above, just formatted for reportlab
    doc = SimpleDocTemplate("IAM_Report.pdf", pagesize=A4)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("AWS IAM Security Audit Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Account: {account_id} | Region: {region} | Time: {time_str}", styles["Normal"]),
        Spacer(1, 10),
    ]
    table_data = [["Severity", "Resource", "Policy", "Issue"]]
    for f in findings:
        table_data.append([f["Severity"], f["Resource"], f["Policy"], f["Issue"]])

    t = Table(table_data, colWidths=[60, 90, 90, 240])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)
    doc.build(story)

    print(f"\n[+] {len(findings)} findings -> findings.json, IAM_Report.html, IAM_Report.pdf")


def main():
    session = boto3.session.Session()
    sts = session.client("sts")
    iam = session.client("iam")

    account_id = sts.get_caller_identity()["Account"]
    region = session.region_name or "aws-global"

    print(f"scanning account {account_id}...\n")
    findings = scan_account(iam)

    print("\n--- findings ---")
    for f in findings:
        print(f"[{f['Severity']}] {f['Resource']} ({f['Policy']}) -> {f['Issue']}")

    generate_reports(findings, account_id, region)


if __name__ == "__main__":
    main()
