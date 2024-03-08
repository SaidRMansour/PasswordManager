# Password Manager Security Model
![.NET](https://img.shields.io/badge/.NET-5C2D91?style=for-the-badge&logo=.net&logoColor=white)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)


This document outlines the security model of the Password Manager, focusing on encryption techniques, key management, and additional security measures to protect user data against unauthorized access and other security threats.

## Encryption

### Data Encryption

- **User Passwords Encryption**: All user passwords are encrypted using the Advanced Encryption Standard (AES) with a 256-bit key. AES-256 is chosen for its strength and resilience against cryptanalysis attempts.
- **Connection Encryption**: Secure communication is established using TLS/SSL for all network transmissions between client and server, if applicable, to prevent interception and alteration of data during transit.

## Key Management

### Master Password Derivation

- **Technical Process**: The user's master password, combined with a unique salt, is transformed into an encryption key using a Key Derivation Function (KDF) such as PBKDF2, bcrypt, or Argon2 with a high iteration count. This process is designed to be secure against brute force and rainbow table attacks.
- **Key Storage**: Encryption keys are never stored in plain text. The derived key from the master password is kept in application memory during the user session and securely deleted upon logout or timeout.
- **Salt Storage**: Salts are stored along with the user's data in the database to enable key derivation during authentication, without the possibility of deriving the master password.

## Authentication and Access Control

### Secure Authentication

- **Process**: Users are authenticated by entering their master password, from which the system generates an encryption key used to decrypt a sample or "unlock" token. This process validates the correctness of the entered password without storing the password itself.
- **Session Management**: Sessions are securely managed with unique session identifiers and automatic timeout for inactive sessions, reducing the risk of session hijacking.

## Security Measures

### Protection Against Common Threats

- **Model**: The security model addresses the OWASP Top 10 threats through encryption, secure key handling, and safe authentication practices. This includes protection against SQL injection, cross-site scripting (XSS), and other web-based attacks, as relevant.
- **Backup and Recovery**: Secure backup procedures are established to enable recovery of user data in case of loss or corruption. Backup data is encrypted and protected in the same manner as primary data.

## Auditing and Monitoring

### Security Audits

- **Process**: Regular, rule-based audits of security practices and code to identify and correct potential vulnerabilities.
- **Monitoring**: System activity monitoring to detect and respond to unusual behavior or security incidents.

## Note

In this demo, a real database will not be used. Instead, a **MemoryStream**, which is a **temporary storage** location for data in the application's memory (RAM), will be utilized. This means the data will only exist as long as the application is running.

## Diagrams
### Masterpassword saving
***
![howtosave](https://github.com/SaidRMansour/PasswordManager/assets/95212978/70a81fad-7fb6-44c4-aac4-7c735b986c38)

### Use Auth to verify
***
![useAuth](https://github.com/SaidRMansour/PasswordManager/assets/95212978/fb711ec7-edb3-49c5-814b-cf11a0a06661)

### Decrypt personal passwords
***
![decrypt](https://github.com/SaidRMansour/PasswordManager/assets/95212978/579fb495-2b21-4551-a441-20b8105d4da1)

### Gui overview (idea)
***
![Gui_2](https://github.com/SaidRMansour/PasswordManager/assets/95212978/f6e89f60-f46b-4520-b2c6-396cf0c34815)


## Conclusion

This security model for a Password Manager emphasizes the importance of strong encryption, careful key handling, and robust security measures to protect user data from unauthorized access and other security threats. By implementing these practices, the system ensures the integrity and confidentiality of user information while maintaining high standards of user security.
