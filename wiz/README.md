# Wiz - Enterprise Cloud Security Posture Assessment
**Environment:** AWS Lab Account (us-east-1) | **Date:** Oct 3, 2026 | **Analyst:** Jerry Owusu-Adjinah

### 1. Executive Summary
Performed a full CSPM scan of 12 AWS resources using Wiz. Identified **3 Critical, 5 High** toxic combinations involving public S3 exposure + over-permissive IAM.
Goal was to demonstrate ability to triage, prioritize, and remediate using least-privilege and IaC.

### 2. Architecture Scanned
- 1x VPC (10.0.0.0/16) - 2 Public, 2 Private Subnets
- 2x EC2 (Amazon Linux 2) - One with IMDSv1 enabled
- 2x S3 Buckets - One with Block Public Access disabled
- 3x IAM Roles - One with \AdministratorAccess\ + trust policy \Principal: "*"\
- 1x Security Group - 0.0.0.0/0 on port 22/3389

### 3. Critical Findings (Wiz)

| ID | Severity | Finding | Resource | Risk |
| :--- | :--- | :--- | :--- | :--- |
| WIZ-001 | **Critical** | S3 Bucket Publicly Readable + Contains PII pattern | \s3://company-backup-xxxx\ | Data Exfiltration |
| WIZ-002 | **Critical** | EC2 with Public IP + Vulnerable Log4j 2.14 + IAM role with s3:* | \i-0a1b2c3d\ | Remote Code Exec -> Privilege Esc |
| WIZ-003 | **Critical** | IAM Role Trust Policy Allows Any AWS Account | \rn:aws:iam::xxxx:role/AdminCrossAccount\ | Account Takeover |

#### Toxic Combination Example (WIZ-002)
Wiz Graph: \Internet Exposure -> EC2 (CVE-2021-44228) -> IAM Role with s3:* -> S3 with Sensitive Data\
This is what hiring managers want to see you understand.

### 4. Remediation & Hardening (What I Did)

**A. S3 (WIZ-001):**
\\\ash
aws s3api put-public-access-block --bucket company-backup-xxxx --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
aws s3api put-bucket-encryption --bucket company-backup-xxxx --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
\\\

**B. EC2 (WIZ-002):**
- Enforced IMDSv2: \ws ec2 modify-instance-metadata-options --instance-id i-0a1b2c3d --http-tokens required --http-endpoint enabled\
- Patched Log4j: \sudo yum update log4j\
- Replaced SG: Removed 0.0.0.0/0 SSH, added my IP /32 only

**C. IAM (WIZ-003) - Least Privilege Fix:**
Before: \AdministratorAccess\
After - Custom Policy I wrote:
\\\json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": ["arn:aws:s3:::company-backup-xxxx", "arn:aws:s3:::company-backup-xxxx/*"],
    "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
  }]
}
\\\

### 5. Terraform Preventative Control
Created \/terraform/s3_secure_baseline.tf\ to prevent drift:
\\\hcl
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls   = true
  block_public_policy = true
}
\\\

### 6. Evidence (Screenshots to add here)
- \./evidence/wiz-dashboard-criticals.png\
- \./evidence/s3-public-block-enabled.png\
- \./evidence/iam-policy-before-after.png\

### 7. Key Takeaways for Security
1. Always think in attack paths, not single findings
2. IMDSv2 + Least Privilege stops 90% of EC2 -> S3 pivots
3. IaC is the only way to prevent re-introduction of misconfig

> Tools: Wiz, AWS CLI, IAM Access Analyzer, Prowler, Terraform
