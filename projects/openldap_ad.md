# Implementation of OpenLDAP and Active Directory for Identity Management

Identity and Access Management (IAM) is an essential component of modern cybersecurity. Through policies, processes, and technologies, it enables organizations to manage users, credentials, and permissions in a centralized, secure, and efficient manner.

This project documents the implementation of two widely used enterprise solutions: **[OpenLDAP](https://www.openldap.org/)** on Ubuntu Linux and Active Directory on Windows Server.

---

## Importance of Identity Management

Adopting an IAM system not only strengthens security, but also improves productivity and regulatory compliance.

- **Operational efficiency**: centralizes access management and facilitates the use of Single Sign-On (SSO).  
- **Reduction of human risk**: robust authentication policies prevent security breaches caused by user errors.  
- **Regulatory compliance**: enables centralized enforcement of security policies and simplifies audits.  

**Image 1 (IAM diagram within the enterprise)**  

---

## OpenLDAP Implementation on Ubuntu Server

**Lab Environment**

- Ubuntu Server 22.04 LTS  
- 2 GB RAM, 1 vCPU, 127 GB HDD  
- NAT network  

**Installation and Basic Configuration**

1. Initial configuration of time zone and opening required ports (22 for SSH, 389 for LDAP).  
2. Installation with:  

   ```bash
   sudo apt install slapd ldap-utils
   ```
3. Domain definition: `dc=Cybersec2lab,dc=net`.

4. Creation of Organizational Units (OUs) and departmental groups such as IT, HR, and Sales.
   
<img width="569" height="517" alt="image" src="https://github.com/user-attachments/assets/79719392-b967-4026-86ef-9cb0bdb7b4df" />

## Password Policies

The **ppolicy** module was enabled with the following conditions:

- Minimum password length of 8 characters.
- History of 5 previous passwords.
- Mandatory password change at first login.
- Configured password expiration.

## Administration with phpLDAPadmin

Management was carried out through the graphical interface **phpLDAPadmin**, accessed via an **SSH tunnel** on local port `8080`.  
During the process, security policies were validated when creating test users.

---

# Active Directory Implementation on Windows Server

### 1. Server Preparation

- Configuration of the **hostname** and **static IP address**.  
- Enabling essential ports:
  - **LDAP (389)**
  - **Kerberos (88)**
  - **DNS (53)**
  - **RDP (3389)**

### 2. Installation and Configuration

1. Installation of Active Directory Domain Services.  
2. Promotion of the server to Domain Controller, creating a new forest and domain.  
3. Configuration of the DSRM recovery mode password.  

<img width="624" height="431" alt="image" src="https://github.com/user-attachments/assets/32254deb-6043-4540-8769-41f4e4451f0b" />

### 3. Organization and Policies

- OUs were created for the following departments:
  - IT  
  - HR  
  - Sales  
  - Accounting  
  - Management  

- Users were grouped into global groups according to each department.  

### Policies Applied through Group Policy Management

- Minimum password length of 8 characters with complexity enabled.  
- History of 5 previous passwords.  
- Password expiration every 90 days.  

<img width="266" height="163" alt="Captura de pantalla 2025-09-06 214604" src="https://github.com/user-attachments/assets/b192bc65-0c8e-465a-9818-c8b972a6c7b0" />

## Remote Administration

Administration was validated through the installation of RSAT (Remote Server Administration Tools) and the use of RDP, confirming remote management of users and policies.

<img width="1536" height="1024" alt="686286b2-2a73-4ea0-80eb-faa8cdd6ee66" src="https://github.com/user-attachments/assets/59f13205-f779-46ff-b0a1-f103b1332aab" />

---

## Conclusions

The implementation of OpenLDAP and Active Directory demonstrates how both technologies fulfill the objective of centralizing identity management, although each follows a different approach:

- OpenLDAP offers flexibility and customization, making it ideal for Linux environments with a strong open-source focus.

- Active Directory integrates naturally within Windows ecosystems and provides more intuitive management tools.

Both solutions represent foundational pillars in the cybersecurity strategy of any organization seeking to strengthen identity and access control.
