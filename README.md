## Documentation for Phishing Course on LetsDefend

### Lab Title: **Phishing Detection and Response using LetsDefend**

**Date**: YYYY-MM-DD  
**Platform**: LetsDefend

### Lab Overview:
In this phishing course, I simulated the role of a SOC Analyst to detect, analyze, and respond to a phishing incident. I examined a phishing email, identified key phishing indicators, and mitigated the risks associated with the phishing attempt.

---

### Objectives:
- Identify and analyze phishing emails.
- Investigate and extract key indicators from email headers, body, and attachments.
- Utilize SOC tools (SIEM, email gateways) to detect phishing campaigns.
- Respond to the phishing incident by taking corrective actions.

### Tools Used:
- LetsDefend SOC Platform
- SIEM (for log analysis)
- Email Header Analysis
- Incident Response playbook

---

### Step-by-Step Documentation:

#### Step 1: **Phishing Email Analysis**

**Objective**: Identify key indicators in the email that suggest it is a phishing attempt.

1. **Check the email header**: 
   - Look for discrepancies in the "From" and "Reply-To" addresses.
   - Analyze the "Received" fields for signs of email spoofing.
   - Examine SPF, DKIM, and DMARC records for authentication failures.

   Example:
   ```
   From: "Customer Support" <support@example.com>
   Reply-To: "support@maliciousdomain.com"
   SPF: Fail
   ```

2. **Analyze the email body**:
   - Look for suspicious links. Hover over URLs and compare the displayed link with the actual URL.
   - Check for urgent language, asking the recipient to act immediately or provide personal information.

   Example of malicious URL:
   ```
   https://securelogin-example.com/login?user=1234
   ```

3. **Inspect attachments**:
   - Any attachments should be treated as suspicious until proven otherwise.
   - In some cases, attachments were malicious and required sandbox analysis to confirm if they contained malware.

---

#### Step 2: **Investigating the Phishing Indicators**

**Objective**: Extract and analyze information about the phishing attempt from email headers, URLs, and attachments.

1. **URL Analysis**:
   - Use tools like VirusTotal or URLScan.io to analyze the URL.
   - Check for the domain’s reputation, whether it’s flagged as malicious.

2. **Log Analysis using SIEM**:
   - Check email logs to see if the phishing email was sent to multiple recipients.
   - Search for any user clicks on phishing links or downloads of attachments.
   - Review the network traffic logs to see if any suspicious IP addresses accessed the network.

---

#### Step 3: **Responding to the Phishing Incident**

**Objective**: Take actions to contain and remediate the phishing attempt.

1. **Block malicious domains**:
   - Use the email gateway or firewall to block the domain/IP address from which the phishing email originated.

2. **Notify the affected user(s)**:
   - Inform the users who received the phishing email and instruct them to avoid clicking any links or opening attachments.
   - If the user has clicked the link, enforce a password reset for their account.

3. **Report the phishing email**:
   - Report the phishing email to a third-party phishing database (e.g., PhishTank) to contribute to the security community.

---

### Findings:

- The phishing email originated from a spoofed domain.
- The URL led to a credential-harvesting website.
- Email was sent to multiple users in the organization.
- One user clicked the link but no credentials were compromised due to swift action.

### Lessons Learned:
- Phishing attacks can be easily detected through careful analysis of email headers and URLs.
- Training users on how to recognize phishing attempts is critical to reduce the risk.
- Automated incident response using tools like SIEM and email gateways is essential for prompt detection and response.

---

### Conclusion:
This lab exercise through LetsDefend provided practical experience in phishing detection and response, honing skills required for working in a SOC environment. Identifying phishing indicators and responding to threats in real-time is crucial for maintaining organizational security.

---

This markdown is now ready to be copied and pasted into your GitHub repository. It highlights your key actions and insights from the phishing course on LetsDefend and serves as a useful guide for others who want to understand phishing detection and response.
