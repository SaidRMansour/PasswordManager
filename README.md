# Password Manager Security Model
![.NET](https://img.shields.io/badge/.NET-5C2D91?style=for-the-badge&logo=.net&logoColor=white)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)


This document outlines the security model of the Password Manager, focusing on encryption techniques, key management, and additional security measures to protect user data against unauthorized access and other security threats.


# Instructions to Run the Application

This project is developed in Visual Studio using .NET 8.0 and cannot be run with lower versions due to incompatibilities with some NuGet packages.

## Prerequisites

- .NET 8.0 SDK installed on your machine. You can download it from [here](https://dotnet.microsoft.com/en-us/download/dotnet/8.0).

## Running the Application in Visual Studio

1. Open the project in Visual Studio.
2. To run the project, press the "Play" button (also known as the "Start Debugging" button) in the toolbar at the top of the Visual Studio window.

## Running the Application via Terminal

Alternatively, you can run the application from the terminal using the .NET CLI. This option might be available depending on your project setup. Here is how you can do it:

1. Open a terminal.
2. Navigate to the project directory.
3. Run the following command:

   ```bash
   dotnet run

## Additional Steps for Mac Users

After downloading .NET 8.0, Mac users need to ensure that Visual Studio uses the .NET 8 SDK if it's installed. To do this:

1. Open Visual Studio.
2. In the menu bar at the top of the screen, select "Visual Studio" > "Preferences".
3. Navigate to "Other" > "Preview Features".
4. Check the option "Use the .NET 8 SDK if installed".
5. Restart Visual Studio for the changes to take effect.

By following these instructions, you should be able to run and debug the application successfully on your machine.

# Screenshots of the product
### Login Page
<img width="427" alt="Skærmbillede 2024-03-17 kl  15 39 05" src="https://github.com/SaidRMansour/PasswordManager/assets/95212978/bd7004af-d918-45f9-a728-0268bd3cdabf">

### Dashboard
<img width="1728" alt="Skærmbillede 2024-03-17 kl  15 39 21" src="https://github.com/SaidRMansour/PasswordManager/assets/95212978/8e5fc394-5952-4bac-9a67-3d4ddf4bf830">

### Add Password
<img width="1727" alt="Skærmbillede 2024-03-17 kl  15 39 41" src="https://github.com/SaidRMansour/PasswordManager/assets/95212978/76a71f66-68d4-4817-8d31-41c0aa56cfa4">

### Show Password
<img width="1722" alt="Skærmbillede 2024-03-17 kl  15 39 59" src="https://github.com/SaidRMansour/PasswordManager/assets/95212978/b592d8d3-0167-4f91-b34d-206f4add2308">

### Generate Password (including special chars)
<img width="1728" alt="Skærmbillede 2024-03-17 kl  15 40 13" src="https://github.com/SaidRMansour/PasswordManager/assets/95212978/78f49a7c-4e38-4fbf-be39-3db5875c5a4e">

### Generate Password (without special chars)
<img width="1728" alt="Skærmbillede 2024-03-17 kl  15 40 23" src="https://github.com/SaidRMansour/PasswordManager/assets/95212978/cfd41095-9ddb-4585-b220-5d680b0b54a8">

# Discussion about security of the product
In developing this application, we have taken several measures to enhance security and protect against potential threats. Our security strategy is designed to defend against a variety of threat actors, including hackers, malicious insiders, automated bots, and even curious users who might inadvertently cause security issues. Here is an overview of the key security measures implemented and the threat actors they are designed to mitigate:

## 1. Session Key Verification

* **Threat Actors Targeted:** Impersonators and unauthorized users.

* **Protection Mechanism:** Every action method in the application checks the session key to ensure that requests are authenticated. This measure is crucial for preventing unauthorized access to sensitive functionalities and data, effectively countering attempts by hackers to impersonate legitimate users.

## 2. Session Management

* **Threat Actors Targeted:** Attackers exploiting session hijacking and fixation.

* **Protection Mechanism:**
```csharp
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); // Sessions expire after 30 minutes of inactivity.
    options.Cookie.HttpOnly = true; // Prevents client-side scripts from accessing the session cookie.
    options.Cookie.IsEssential = true; // Marks the session cookie as essential for the application to function.
});
```
These settings help mitigate attacks by limiting the lifespan of sessions and restricting access to session cookies, directly addressing the tactics of threat actors focused on session hijacking.


## 3. Centralized Logic in Services

* **Threat Actors Targeted:** Broad spectrum of attackers, including those exploiting business logic vulnerabilities.

* **Protection Mechanism:** Encapsulating all business logic within services not only adheres to the principle of separation of concerns but also centralizes the security logic. This makes it easier to manage, audit, and secure against various attacks, including business logic exploitation and unauthorized data access.

## 4. Potential Enhancements and OWASP Top 10 Protection

* **Threat Actors Targeted:** A wide range of attackers exploiting common web vulnerabilities.

* **Planned Enhancements:** Future security enhancements will focus on adopting HTTPS for all communications to protect against man-in-the-middle attacks, further fortifying the application against OWASP Top 10 vulnerabilities such as Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF). These measures are especially targeted at attackers using sophisticated techniques to exploit well-known vulnerabilities.

By focusing on session management, secure coding practices, and considering some of the OWASP Top 10 risks, this application aims to provide a secure environment against common threats and vulnerabilities. The security measures are designed with a clear understanding of the threat landscape and the types of actors that pose risks to web applications.

# Security Model Overview

Our application employs a robust security model that encompasses encryption, key handling, and session management to safeguard user data and ensure secure operations. Here’s a detailed breakdown of our approach:

## Encryption and Key Handling

- **Data Encryption**: We use the Advanced Encryption Standard (AES) for data encryption, ensuring that sensitive information such as user passwords are encrypted before storage. AES is a widely recognized encryption standard that provides a high level of security.

- **Dynamic Key Generation**: Encryption keys are generated dynamically using the Password-Based Key Derivation Function 2 (PBKDF2). This method uses a master password and a salt to produce a strong encryption key. The salt, a random value, enhances security by ensuring that the same password generates different keys on each instance.

- **Secure Key Storage**: The encryption keys, along with a salt and an initialization vector (IV) for AES, are securely stored. The IV ensures that the encryption process produces unique ciphertext for the same plaintext when encrypting multiple times.

- **Password Generation**: Our application includes a password generator that creates strong, complex passwords based on specified criteria, such as length and the inclusion of special characters. This feature helps users generate passwords that are resistant to common attacks like brute force.

## Session Management

- **Session Key Verification**: To maintain a secure session state, our application verifies the session key with every action method. This ensures that each request is authenticated and authorized, reducing the risk of session hijacking.

- **Session Configuration**: Sessions are configured with an idle timeout, an HTTPOnly cookie attribute, and marked as essential. The idle timeout limits the session duration, reducing exposure to unauthorized access. The HTTPOnly attribute prevents client-side scripts from accessing the session cookie, mitigating the risk of cross-site scripting (XSS) attacks.

## Security Measures Against Common Threats

- **Protection Against OWASP Top 10 Risks**: While the current implementation focuses on key security aspects due to time and development environment constraints, future enhancements will aim to address the OWASP Top 10 Web Application Security Risks more comprehensively. This includes implementing HTTPS for secure data transmission and adding measures to protect against XSS and Cross-Site Request Forgery (CSRF).

- **Centralized Security Logic**: By centralizing our business logic within services, we enhance the maintainability and security of our application. This structure facilitates focused security audits and updates, ensuring that our security measures remain effective against evolving threats.

Our security model is designed with a deep understanding of the threat landscape and adheres to best practices in encryption, key management, and session security. By continually assessing and enhancing our security measures, we strive to provide a secure and reliable platform for our users.

## Note

In this demo, a real database will not be used. Instead, a **JSON file**, which will be located in the **Solution folder**.

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

Our Password Manager prioritizes robust security through advanced encryption, rigorous key management, and strategic security measures to protect against unauthorized access and threats. Utilizing the Advanced Encryption Standard (AES) and dynamic key generation with PBKDF2, we ensure data integrity and confidentiality. Our system enhances security with HTTPOnly cookies and session timeouts, alongside a built-in password generator for creating secure passwords.

We're committed to defending against the OWASP Top 10 vulnerabilities, continuously updating our security practices in response to emerging threats. This commitment ensures our platform remains a secure environment for our users' sensitive information.

The design of our Password Manager is tailored to counter a wide range of cyber threats, maintaining a vigilant and adaptive security posture. Our focus on delivering a secure platform underscores our dedication to user trust and data protection, positioning our Password Manager as a standard-bearer in data security.
