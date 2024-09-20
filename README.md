## Documentation for Phishing Module on TryHackMe

### Lab : **Phishing Detection and Analysis**

### Lab Overview:
In this phishing module, I simulated the role of a SOC Analyst to learn how to detect and analyse to a phishing incident. I examined a phishing email, identified key phishing indicators, and mitigated the risks associated with the phishing attempt.

---

### Objectives:
- Identify and analyze phishing emails.
- Investigate and extract key indicators from (1)email headers, (2)body, and (3)attachments.
- Utilize SOC tools (virustotal, mxtoolbox) to analyse phishing emails.
- Respond to the phishing incident by taking corrective actions.

---

### Step-by-Step Documentation:

#### Step 1: **Phishing Email Analysis**

**Objective**: Identify key indicators in the email that suggest it is a phishing attempt.

**a. Check the email header**: 
   - Look for discrepancies in the email's "From" address, "Subject", "To" address and "Date".
   - Additionally, look for discrepancies in the "X-Originating IP" and "Reply-To" address.
   - Analyze the "Received" fields for signs of email spoofing.
   - Examine SPF, DKIM, and DMARC records for authentication failures.

   **Example:**
   
![Email Header Analysis 4](https://github.com/user-attachments/assets/fed3a60a-8472-4f9a-8d01-be8d548c627f)

*Figure 1: Investigate key indicators in the Email Header: (1)"From" Address, (2)"Subject", (3)"To" Address and (4)"Date".*

![Email Header Analysis](https://github.com/user-attachments/assets/ace2211a-3505-41eb-8559-c3cc1d4bdfc1)

*Figure 2: Investigate key indicators in the raw message (.eml): In this example, you can investigate the X-Originating IP and the "Reply-To" address.*

![DMARC](https://github.com/user-attachments/assets/d6901f40-b5f6-42f3-8c55-2c793b520956)

*Figure 3: Investigate key indicators in the raw message (.eml): Examine SPF, DKIM, and DMARC records for any authentication failures.*

**b. Analyze the email body**:
   - Look for suspicious links. Hover over URLs and compare the displayed link with the actual URL.
   - Check for urgent language, asking the recipient to act immediately or provide personal information. Additionally, look out for poor grammar and/or typos.

   **Example of using urgency for phishing:**
   
![cancel order urgency email](https://github.com/user-attachments/assets/dd9f34a1-2998-4642-b1b5-75393f95e978)

*Figure 4: An example of phishing capitalising on urgent language to click on the cancel button which will redirect to another link.*

   **Example of hovering over URLs:**

![link](https://github.com/user-attachments/assets/5daa492c-6784-46d5-a6de-11caf8faf57d)

*Figure 5: An example hovering over URL to be examined.*

**c. Inspect attachments**:
   - Any attachments should be treated as suspicious until proven otherwise.
   - In some cases, attachments were malicious and required sandbox analysis to confirm if they contained malware.

---

#### Step 2: **Investigating to the Phishing Artifacts**

**Objective**: Extract and analyze information about the phishing attempt from email headers, URLs, and attachments.

**a. Domain/URL/Attachment Analysis**:
   - Use tools like VirusTotal or URLScan.io to analyze the URL [Static Analysis].
   - Check for the domain’s reputation, whether it’s flagged as malicious [Static Analysis].
   - Executing or interacting with the phishing artifact in a controlled environment [Dynamic Analysis].

   **Example of Static Analysis:**

![image](https://github.com/user-attachments/assets/df42e614-1b09-45f5-922d-360cc09f6650)

*Figure 6: Utilising tools like VirusTotal to examine the attachment. In this example, the attachment's SHA256 is extracted and is used in VirusTotal.*

   **Example of Dynamic Analysis:**

![image](https://github.com/user-attachments/assets/d115e294-be74-412b-8db5-6497576da820)

*Figure 7: Utilising tools like Any.Run (interactive online sandbox platform) to examine the attachment.*

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

**Additionally, there are various actions a defender can take to help protect the users from falling victim to a malicious email.** 

**Some examples of these actions are listed below:**

   - Email Security (SPF, DKIM, DMARC)
   - SPAM Filters (flags or blocks incoming emails based on reputation)
   - Email Labels (alert users that an incoming email is from an outside source)
   - Email Address/Domain/URL Blocking (based on reputation or explicit denylist)
   - Attachment Blocking (based on the extension of the attachment)
   - Attachment Sandboxing (detonating email attachments in a sandbox environment to detect malicious activity)
   - Security Awareness Training (internal phishing campaigns)

---

### Lessons Learned:
- Phishing attacks can be easily detected through careful analysis of email headers and URLs.
- Training users on how to recognize phishing attempts is critical to reduce the risk.
- Automated incident response using tools like SIEM and email gateways is essential for prompt detection and response.

---

### Conclusion:
This lab exercise through TryHackMe provided practical experience in phishing detection and response, honing skills required for working in a SOC environment. Identifying phishing indicators and responding to threats in real-time is crucial for maintaining organizational security.

---
