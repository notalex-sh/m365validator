# O365 Recon 🕵️‍♂️

A simple and effective OSINT tool for passively checking the validity of Microsoft 365 domains and user accounts.

---

## Quickstart Guide

### 1. Installation

This project requires Python 3 and Git.

1.  **Clone the Repository:** Open your terminal and clone the project repository from GitHub.
    ```bash
    git clone https://github.com/notalex-sh/o365-recon.git
    ```

2.  **Navigate to the Directory:** Change into the newly created project folder.
    ```bash
    cd o365-recon
    ```

3.  **Install Dependencies:** Install the necessary packages using the `requirements.txt` file.
    ```bash
    pip install -r requirements.txt
    ```

### 2. Usage

Run the script from your terminal, choosing one of the two modes.

#### Check a Domain
Use the `-d` or `--domain` flag followed by the domain name.

```bash
python o365_recon.py -d company.com
```

#### Check a User
Use the `-u` or `--user` flag followed by the email address you want to validate.

```bash
python o365_recon.py -u employee123@company.com
```

### 3. Understanding the Output

The tool provides simple, color-coded feedback:
* **Green `✓`**: Indicates that the domain or user is **VALID**.
* **Red `✗`**: Indicates that the domain or user is **INVALID** or was not found.

For every user check, a note is provided to remind you of the difference between a login ID and a friendly email alias.

---

## How It Works: The Theory

The tool's effectiveness comes from querying **publicly accessible, unauthenticated Microsoft endpoints** that are part of the standard M365 login process. It doesn't hack anything; it simply asks Microsoft's servers questions they are designed to answer publicly.

### Domain Validation

To check if a domain like `company.com` is used by Microsoft 365, the tool sends a request to the `getuserrealm.srf` endpoint. This is a normal first step in Microsoft's login flow to determine *how* a user should be authenticated.

The tool looks at the **`NameSpaceType`** value in the server's response:
* **`Managed`**: The domain is a standard M365 tenant, managed directly by Microsoft. **The domain is valid.**
* **`Federated`**: The domain is linked to a different authentication system (like a company's own login server). **The domain is valid.**
* **`Unknown`**: Microsoft's servers do not recognize the domain. **The domain is not valid** or not associated with M365.

### User Validation

To check if a user account exists, the tool queries the `GetCredentialType` endpoint. This endpoint's job is to figure out if a username exists before the user is asked for a password.

The crucial information is the **`IfExistsResult`** value returned by the server:
* A result of **`0`**, **`5`**, or **`6`** indicates that an identity with that username exists. **The user is valid.**
* A result of **`1`** means no such identity was found. **The user is invalid.**

An important detail is that this process validates the user's **login identity**, officially known as the User Principal Name (UPN). In many organizations, this is different from a person's "friendly" email address. For example:
* **Friendly Email:** `jane.doe@company.com`
* **Login ID / UPN:** `e12345@company.com`

This tool will find `e12345@company.com` to be **VALID** but may find `jane.doe@company.com` to be **INVALID** if it's only configured as an alias and not a primary login ID.
