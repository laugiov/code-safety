/**
 * @name Hardcoded Credentials
 * @description Detects hardcoded secrets, passwords, API keys, and other credentials
 *              that should be stored securely in environment variables or secrets managers.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id py/vulnshop-hardcoded-credentials
 * @tags security
 *       external/cwe/cwe-798
 *       external/owasp/owasp-a02
 */

import python

/**
 * A string literal that appears to be a hardcoded secret.
 */
class HardcodedSecret extends StrConst {
  string secretType;

  HardcodedSecret() {
    // AWS Access Key ID (starts with AKIA)
    (
      this.getText().regexpMatch("AKIA[0-9A-Z]{16}") and
      secretType = "AWS Access Key ID"
    )
    or
    // AWS Secret Key (40 character base64-like string)
    (
      exists(AssignStmt a, Name n |
        a.getValue() = this and
        a.getTarget(0) = n and
        n.getId().regexpMatch("(?i).*(aws_secret|secret_access_key).*")
      ) and
      this.getText().length() >= 30 and
      secretType = "AWS Secret Access Key"
    )
    or
    // Django SECRET_KEY
    (
      exists(AssignStmt a, Name n |
        a.getValue() = this and
        a.getTarget(0) = n and
        n.getId() = "SECRET_KEY"
      ) and
      this.getText().length() >= 20 and
      not this.getText().regexpMatch("(?i).*(changeme|example|placeholder|xxx|your_secret).*") and
      secretType = "Django Secret Key"
    )
    or
    // Stripe API keys
    (
      this.getText().regexpMatch("sk_live_[0-9a-zA-Z]{24,}") and
      secretType = "Stripe Live Secret Key"
    )
    or
    (
      this.getText().regexpMatch("sk_test_[0-9a-zA-Z]{24,}") and
      secretType = "Stripe Test Secret Key"
    )
    or
    (
      this.getText().regexpMatch("pk_live_[0-9a-zA-Z]{24,}") and
      secretType = "Stripe Live Publishable Key"
    )
    or
    // Generic API key pattern
    (
      exists(AssignStmt a, Name n |
        a.getValue() = this and
        a.getTarget(0) = n and
        n.getId().regexpMatch("(?i).*(api_key|apikey|api_secret).*")
      ) and
      this.getText().length() >= 16 and
      not this.getText().regexpMatch("(?i).*(example|placeholder|xxx|your_|changeme).*") and
      secretType = "API Key"
    )
    or
    // Database password
    (
      exists(AssignStmt a, Name n |
        a.getValue() = this and
        a.getTarget(0) = n and
        n.getId().regexpMatch("(?i).*(password|passwd|pwd).*")
      ) and
      this.getText().length() >= 4 and
      this.getText() != "" and
      not this.getText().regexpMatch("(?i).*(example|placeholder|xxx|changeme|password).*") and
      secretType = "Password"
    )
    or
    // Database password in DATABASES dict
    (
      exists(Dict d, KeyValuePair kvp |
        kvp = d.getAnItem() and
        kvp.getKey().(StrConst).getText() = "PASSWORD" and
        this = kvp.getValue() and
        this.getText().length() >= 4 and
        this.getText() != "" and
        not this.getText().regexpMatch("(?i).*(example|placeholder|xxx|changeme).*")
      ) and
      secretType = "Database Password"
    )
    or
    // Private key content
    (
      this.getText().regexpMatch("-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----.*") and
      secretType = "Private Key"
    )
    or
    // JWT Secret
    (
      exists(AssignStmt a, Name n |
        a.getValue() = this and
        a.getTarget(0) = n and
        n.getId().regexpMatch("(?i).*(jwt_secret|jwt_key|token_secret).*")
      ) and
      this.getText().length() >= 16 and
      secretType = "JWT Secret"
    )
    or
    // GitHub Token
    (
      this.getText().regexpMatch("gh[pousr]_[A-Za-z0-9_]{36,}") and
      secretType = "GitHub Token"
    )
    or
    // Slack Token
    (
      this.getText().regexpMatch("xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}") and
      secretType = "Slack Token"
    )
    or
    // SendGrid API Key
    (
      this.getText().regexpMatch("SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}") and
      secretType = "SendGrid API Key"
    )
    or
    // Twilio Account SID/Auth Token pattern
    (
      this.getText().regexpMatch("AC[a-f0-9]{32}") and
      secretType = "Twilio Account SID"
    )
  }

  string getSecretType() { result = secretType }
}

/**
 * Exclude test files and examples
 */
predicate isTestOrExample(File f) {
  f.getAbsolutePath().regexpMatch(".*/(test|tests|example|examples|mock|fixture|sample)/.*")
  or
  f.getBaseName().regexpMatch("(test_.*|.*_test|example_.*|sample_.*)\\.py")
}

from HardcodedSecret secret, File f
where
  secret.getLocation().getFile() = f and
  not isTestOrExample(f)
select secret,
  "Hardcoded " + secret.getSecretType() +
    " found. Use environment variables or a secrets manager instead."
