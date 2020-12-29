# Web App Pre Release Checks

## 1. Configuration

Application configuration may contains sensitive data such as passwords, access keys or certificates. That data should be encrypted or provided by secure channels.

### 1.1 Configuration files

The data stored in XML, JSON or any structured format.

_DO NOT store sensitive data in plain text_

- [ ] The data should be encrypted using any algorithm: base64, RSA etc.

_DO NOT commit sensitive data to SCC (source control system, e.g. git)_

- [ ] In **development** environment the [Secret Manager](https://docs.microsoft.com/en-us/aspnet/core/security/app-secrets?view=aspnetcore-3.1&tabs=windows#secret-manager) can be used.
- [ ] In **production** environment should be stored in the [Azure Key Vault](https://docs.microsoft.com/en-us/aspnet/core/security/key-vault-configuration) or web application configuration.

### 1.2 Command line arguments

Configuration variables are passed to the application at start.

- [ ] In **development** environment can be passed in application run command.
- [ ] In **production** environment should be configured on deployment.

### 1.3 Environment variables

Application reads configuration variables from environment.

- [ ] In **development** environment can be configured using OS utilities (e.g. SET or ENV) or IDE.
- [ ] In **production** environment should be configured on deployment.

## 2. Transport

### 2.1 HTTPS

The data transmitted between client and server is encrypted by SSL or TLS.

- [ ] Enforce using HTTPS transport ([read more](https://docs.microsoft.com/en-us/aspnet/core/security/enforcing-ssl))
- [ ] Configure automatic certificate rotation on web server

### 2.2 CORS

You may want to restrict your API from using on external web sites. All browsers support and follow Cross-Origin Resource Sharing (CORS) policies. By default if CORS not enabled, nobody can access API from another domain. But it is good to be able configure it on web server.

- [ ] In **development** environment can be allowed from any domain.
- [ ] In **production** environment should be restricted to known domains.

[Read more](https://docs.microsoft.com/en-us/aspnet/core/security/cors)

## 3. Authentication

### 3.1 Basic

- [ ] User name and password passed in Authorization header.

` Authorization: Basic base64(username + ":" + password)`

- [ ] Always use secure transport ([HTTPS](#https))

### 3.2 Cookies

#### 3.2.1 SameSite

[Read more](https://docs.microsoft.com/en-us/aspnet/core/security/samesite)

### 3.3 OAuth

- [ ] Any client should send access token in Authorization header.

`Authorization: Bearer <ACCESS_TOKEN>`

[Read more](https://oauth.net/2/)

### 3.4 JWT

Json Web Token (JWT) 

- [ ] Should be signed with strong cryptographic algorithm
- [ ] May be encrypted
- [ ] Should be validated

## 4. Authorization

- [ ] Private API should be retricted only for authenticated users
- [ ] Access control may be configured to allow or deny operations

### 4.1 RBAC

- [ ] Role-based access control (RBAC) 
- [ ] Make and check user/roles mermission matrix

[Read more](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/roles)

## 5. Code injection

### 5.1 Client-side

- [ ] Any submitted field value should be html-encoded
  > All browsers encode on submitting forms
- [ ] Any rendered field value should be html-encoded
  > Razor by default escapes expression values

### 5.2 Server-side

- [ ] Input data should be validated
  > [Read more](https://docs.microsoft.com/en-us/aspnet/core/mvc/models/validation)
- [ ] Very long content should be rejected
  > [Read more](https://docs.microsoft.com/en-us/aspnet/core/mvc/models/file-uploads)

### 5.3 SQL injection

- [ ] Use built-in parameters in sql command
  > [Read more](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/commands-and-parameters)
- [ ] Avoid using string concatenation or string format
  > Use parameter placeholder instead

## 6. Logging

- [ ] Configure centralized logging (Application Insights, Splunk, etc.)
- [ ] Configure alerts on critical modules

## 7. Metrics

- [ ] Configure centralized metrics server (Prometheus)
- [ ] Configure alerts on critical modules

## 8. Swagger and docs

- [ ] Make sure that enpoint docs are not available on prod

## 9. File Uploading

- [ ] Configure size/format restrictions for uploading files to server
- [ ] Make sure that files cannot be executed from storage
- [ ] Make sure storage has "soft delete" option on
- [ ] Connection to file storage uses encryption 
- [ ] Files are not stored with int ids

## 10. Infrastructure

- [ ] If possible -- move infrastructure to the virtual network

## Captcha

- [ ] Implement CAPTCHA 

# Web App Pentesting Guide

"dgon" - example username or site name

## 1. Fingerprinting Application
- Bruteforce subdomains
- Directory enumeration via Dirb, Dirbuster, BurpSuite Intruder, etc.
- Identidy underlying web client and server technology
- Uncover HTTP/HTTPs services running on ports other than the 80 and 443
- Find leaked email id, passwords using ‘We leak Info’ and ‘Hunter.io’
- Identidy firewall
- Find sensitive information through keywords after crawling entire site. Keywords such as admin, password, todo, http

## 2. Network Testing
- Test for ping (ICMP packets are allowed or filtered)
- DNS testing for zone transfer, missing DNSSEC policies
- Missing DMARC policies
- Perform Nessus scan
- Banner disclosure for open ports and network services
- Find all web and network services other than port 80 and 443
- Perform UDP scan using UDP proto scanner

## 3. Application Features Mapping
- Generate site structure in any mindmap tool
- List all dynamic features
- Add all possible theoritical test cases within your mind map for testing security of those features

## 4. Application Component Audit
- Test SSL/TLS weaknesses using Qualys SSL scanner
- Identify known vulnerabilities in running web and network components using known CVE, searchsploits, Metasploit auxiliaries and exploits

## 5. Session Management Testing
- Identify actual session cookie out of bulk cookies in the application.
- Decode cookies using some standard decoding algorithms such as Base64, hex, URL etc.
- Modify cookie.session token value by 1 bit/byte. Then resubmit and do the same for all token. Reduce the amount of work you need to perform in order to identify which part of token is actually being used and which is not.
- If self-registration is available and you can choose your username, log in with a series of similar usernames containing small variations between them, such as A, AA, AAA, AAAA, AAAB, AAAC, AABA, and so on. If other user-specific data is submitted at login or stored in user profiles (such as an e-mail address)
- Token leakage via Referer header - Untrusted 3rd Party
- Check for session cookies and cookie expiration date/time
- Identify cookie domain scope
- Check for HttpOnly flag in cookie
- Check for Secure flag in cookie if the application is over SSL
- Check for session fixation i.e. value of session cookie before and after authentication
- Replay the session cookie from a different effective IP address or system to check whether server maintains the state of the machine or not.
- Check for concurrent login through different machine/IP
- Check if any user pertaining information is stored in cookie value or not. If yes, tamper it with other user's data.

## 6. Registration Feature Testing
- Check for duplicate registration / Overwrite existing user
- Check for weak password policy
- Check for the stored dgon in username, account name for registration.
- Check for insufficient email verification process
- Weak registration implementation - Allows disposable email addresses
- Overwrite default web application pages by specially crafted username registrations. => After registration, does your profile link appears something as www.dgon.com/dgon ? a. If so, enumerate default folders of web application such as /images, /contact, /portfolio b. Do a registration using the username such as images, contact, portfolio c. Check if those default folders have been overwritten by your profile link or not."

## 7. Authentication Testing
- Username enumeration
- Bypass authentication using various SQL Injections on username and password field. Use combinations of below injections dgon' -- dgon' # dgon'/* ' or 1=1 -- ' or 1=1 # ' or 1=1/* ') or '1'='1 -- ') or ('1'='1 --"
- Auto-complete testing
- Lack of password confirmation on
  - Change email address
  - Change password
  - Manage 2FA
- Is it possible to use resources without authentication? Access violation
- Check if user credentials are transmitted over SSL or not.
- Weak login function - HTTP and HTTPS both are available.
- Test user account lockout mechanism on brute force attack
  - Variation : If server blocks instant user requests, then try with time throttle option from intruder and repeat the process again.
- Bypass rate limiting by tampering user agent to Mobile User agent.
- Bypass rate limiting by tampering user agent to Anonymous user agent.
- Create a password wordlist using cewl command
- Test 0auth login functionality for Open Redirection
  - Use burp 'find' option in order to find parameters such as URL, red, redirect, redir, origin,dest, targetURL, checkout_URL etc.
  - Check the value of these parameter which may contain a URL.
  - Check open redirection for 0auth functionality.
  - Change the URL value to www.dgon.com and check if gets redirected or not. 5) Check if same secret code request can be used multiple times."

## 8. Error Codes Testing
- Generate custom pages such as /dgib.php, dgon.aspx and identify error page
- Add multiple parameters in same post get request using different value and generate error
- Add [], ]], and [[ in cookie values and parameter values to create errors
- Try to generate unusual error code by giving input as /~dgon/%s at the end of website URL
- Fuzz using the Burp Intruder with malicious input and try to generate error codes

## 9. My Account (Post Login) Testing
- Find parameter which uses active account user id. Try to tamper it in order to change the details of other account.
- Create a list of features that are pertaining to a user account only.- Change Email- Change PasswordChange account details (Name, Number, Address, etc.) Try CSRF
- Post login change email id and update with any existing email id. Check if its getting validated on server side or not. Does the application send any new email confirmation link to a new user or not? What if a user does not confirm the link in some time frame?
- Perform all file upload test using extension tampering and file content modifying. Unsafe File upload - - No Antivirus - No Size Limit - File extension Filter Bypass
- Open profile picture in new tab and check the URL. Find email id/user id info. EXIF Geolocation Data Not Stripped From Uploaded Images.
- Check account deletion option if application provides it and confirm that via forgot password feature
- Change email id, account id, user id parameter and try to brute force other user's password
- Check whether application re-authenticates for performing sensitive operation for post authentication features

## 10. Forgot Password Testing
- Failure to invalidate session on Logout and Password reset
- Check if forget password reset link/code uniqueness
- Check if reset link does get expire or not if its not used by the user for certain amount of time
- Find user account identification parameter and tamper Id or parameter value to change other user's password
- Check for weak password policy
- Weak password reset implementation - Token is not invalidated after use
- If reset link have another params such as date and time, then. Change date and time value in order to make active & valid reset link.
- Check if security questions are asked? How many guesses allowed? -> Lockout policy maintained or not?
- Add only spaces in new password and confirmed password. Then Hit enter and see the result.
- Does it display old password on the same page after completion of forget password formality?
- Ask for two password reset link and use the older one from user's email
- Check if active session gets destroyed upon changing the password or not?
- Weak password reset implementation - Password reset token sent over HTTP
- Send continuous forget password requests so that it may send sequential tokens

## 11. Contact Us Form Testing
- Is CAPTCHA implemented on contact us form in order to restrict email flooding attacks?
- Does it allow to upload file on the server?

## 12. Product Purchase Testing
- Buy Now
  - Tamper product ID to purchase other high valued product with low prize
  - Tamper product data in order to increase the number of product with the same prize
- Gift / Voucher
  - Tamper gift/voucher count in the request (if any) to increase/decrease the number of vouchers/gifts to be used
  - Tamper gift/voucher value to increase/decrease the value of voucher in terms of money. (e.g. $100 is given as a voucher, tamper value to increase, decrease money)
  - Reuse gift/voucher by using old gift values in parameter tampering.
  - Check the uniqueness of gift/voucher parameter and try guessing other gift/voucher code.
  - Use parameter pollution technique to add same voucher twice by adding same parameter name and value again with & in the BurpSuite request.
- Add/Delete Product from Cart
  - Tamper user id to delete products from other user's cart.
  - Tamper cart id to add/delete products from other user's cart.
  - Identify cart id/user id for cart feature to view the added items from other user's account.
- Address
  - Tamper BurpSuite request to change other user's shipping address to yours.
  - Try stored-XSS by adding XSS vector on shipping address.
  - Use parameter pollution technique to add two shipping address instead of one trying to manipulate application to send same item on two shipping address.
- Place Order
  - Tamper payment options parameter to change the payment method. E.g. Consider some items cannot be ordered for cash on delivery but tampering request parameters from debit/credit/PayPal/net banking option to cash on delivery may allow you to place order for that particular item.
  - Tamper the amount value for payment manipulation in each main and sub requests and responses.
  - Check if CVV is going in cleartext or not.
  - Check if credit/debit card details are masked or not.
  - Check if application itself process your card details and then perform transaction or it calls any third party payment processing company to perform transaction.
- Track Order
  - Track other user's order by guessing order tracking number

## 13. Flight/Railway/Hotel Booking Testing
- Booking details
  - View/Manage other user's booking details.
  - Check reservation status for other users/behalf of other users.
- Ticket/Voucher
  - View other users vouchers/e-tickets from PRINT option
  - Check if sensitive data is passed in GET request
  - If e-ticket/voucher is sent on email then check for the email flooding attack.
- Refund
  - View other user's refund status.
  - Refund more money than the intended one by parameter manipulation.
  - If refund tracking is allowed then gain other user's refund tracking status.
- Cancellation
  - Gain higher cancellation amount with parameter modifying for amount value.
- Booking
  - Do 1st person booking and add 3 other persons in same prize
  - Hotel - Book normal room - Select Deluxe room in the same prize
  
## 14. Cross-Site Scripting Testing
- Locator: '';!--"<dgon>=&{()}
- Try XSS using XSSstrike tool by Somdev Sangwan
- Upload file using ```'"><img src=x onerror=alert(document.domain)>.txt```
- Standard payload for URI and all inputs:
  - ``` "><img src=x onerror=prompt(document.cookie);><!--```
  - ```"><img src=x onerror=confirm(document.cookie);><!--```
  - ```"><img src=x onerror=alert(document.cookie);><!--```
- If script tags are banned, use <h1> and other HTML tags
- If output is reflected back inside the JavaScript as a value of any variable just use alert(1)
- if " are filtered then use this payload /><img src=d onerror=confirm(/dgon/);>
- Upload a JavaScript using Image file
- Unusual way to execute your JS payload is to change method from POST to GET. It bypasses filters sometimes.
- Tag attribute value
  - Input landed - <input type=”text” name=”state” value=”INPUT_FROM_ USER”>
  - Payload to be inserted - “ onfocus=”alert(document.cookie)"
- Syntax Encoding payload “%3cscript%3ealert(document.cookie)%3c/script%3e"
- ASP.NET IE9 dgon Filter evasion for htmlentities
o &lt;%tag style=”dgon:expression(alert(‘dgon’))”&gt;
o ‹%tag style=”dgon:expression(alert(123))
o ‹%tag style=”dgon:expression(alert(123))”
• Try base64 payload
• If the logout button just performs the redirection then use old classic XSS payload
• Polyglot payload
• Use pure JS payload that worked for many popular websites if your input is reflected back in the JavaScript.

## 15. SQL Injection Testing
- Locator (Error Based)
- Test'"" 123' ""Þ}j%Ùÿ'""'""""';' '""();=,%+-/**/ --«
- If parameter=static_integer_value then follow below method. If id=4, then try id=3+1 or id=6-2 (if page loads in same way, it is vulnerable)
- Use SQLmap to identify vulnerabile parameters
  - Fill form in browser GUI submit it normally.
  - Go to history tab in burpsuite and find the relevent request.
  - Right click and select the option "copy to file".
  - Save file as anyname.txt
  - SQLmap command to run
  - python sqlmap.py -r ~/Desktop/textsqli.txt --proxy=http://127.0.0.1:8080
  - Run SQL injection scanner on all requests

## 16. Open Redirection Testing
- Use burp 'find' option in order to find parameters such as URL, red, redirect, redir, origin, redirect_uri, target etc.
- Check the value of these parameter which may contain a URL.
- Change the URL value to www.dgon.com and check if gets redirected or not.
- Give below URL in web browser and check if application redirects to the www.dgon.com website or not.
  - https://www.target.com/ÿ/www.twitter.com/
  - https://www.target.com//www.twitter.com/
  - https://www.target.com/Ã¿/www.twitter.com/
  - https://www.target.com//www.twitter.com/
- Bypass filter using returnTo=///dgon.com/
- Bypass filter using returnTo=http:///dgon.com/

## 17. Host Header Injection
- Inset new header in the GET/POST request as follows: X-Forwarded-Host: www.dgon.com. If it gets redirected from the target application then its vulnerable. Capture any request, Change the host to google.com and see if its getting redirected or not

## 18. ASP.NET Application Testing
- Check if ASP.net viewstate parameter is encrypted or not
- Check if any ASP configuration is disclosed publicly or not
- Check if error codes reveal the version of ASP.NET used in the application

## 19. CSRF Testing
- Re-use Anti-CSRF token for CSRF attack
- Check if token is validated on server side or not
- Check if token validation for full length or partial length
- Create few dummy account and compare the CSRF token for all those accounts
- Bypass CSRF token using 2 input type fields in for updating user's information in the same HTML file
- Convert POST request to GET and remove _csrf (anti-csrf token) to bypass the CSRF protection.
- Check if the value you are trying to change is passed in multiple parameters such as cookie, http headers along
with GET and POST request.

## 20. XML Injection Testing
- Change the content type to text/xml then insert below code. Check via repeater
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE dgon [
<!ELEMENT dgon ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]><dgon>&xxe;</foo>

## 21. Web Services Testing
- SOAP Message Tampering
  - Brute forcing using *
  - Brute forcing using user credentials
  - Parameter guessing
  - SQL injection using ' " - * )
  - Test for directory traversal
- Test for XML poisoning
- Web services documentation disclosure – Enumeration of services, data types, input types boundaries and limits

## 22. Automated Scanner
- Run automated scanner at least
  - Netsparker
  - BurpSuite Scanner
  - For WordPress – Pecan; For Joomla – Groomsman
  - Nessus for network services scan
  - Nexpose for network services scan
  
## 22. CAPTCHA Testing
- Replay attack
  - Send old captcha value with if accepts then it is vulnerable.
  - Send old captcha value with old session ID, if its accepts then it is vulnerable.
- Check if captcha is retrievable with the absolute path such as
www.dgon.com/internal/captcha/images/24.png
- Check for the server-side validation for CAPTCHA. Remove captcha block from GUI using firebug addon and submit request to the server.
- Check if image recognition can be done with OCR tool?
  - If OCR identifies then report as weak strength of captcha - OCR (Optical Character Recognition)
  
## 23. Other Test Cases (All Categories)
- Check for SSRF Vulnerability by giving www.dgon.com:22 , www.dgon.com:23 etc. Check for the
response page and determine if port 22 is opened in dgon website. If yes then target website is
vulnerable to SSRF vulnerability.
• Check for security headers and at least:
  - X-Frame-Options
  - X-XSS header
  - HSTS header
  - CSP header
  - Referrer-Policy
  - Cache Control
  - Public key pins
- Command injection on CSV export (Upload/Download)
- DDOS using xmlrpc.php
- If website has a feature for importing contacts from .CSV files then
  - Add one contact in your CSV file with the name "><script>alert("dgon")</script>
  - Import contact to the website
  - Check if script getting executed or not.
- CSV Excel Macro Injection
- Find metadata for the downloadable objects
- Review Image files, PDF files and other object's metadata for information leakage
- Test Rich Internet Application RIA cross domain policy; Try to access crossdomain.xml; Try to access clientaccesspolicy.xml
- If you find phpinfo.php file, check for the configuration leakage and try to exploit any network vulnerability.
- Bypass SAML authentication by response tampering
- Testing for Role authorization
  - Check if normal user can access the resources of high privileged users?
  - Forced browsing
  - Insecure direct object reference
  - Parameter tampering to switch user account to high privileged user.
- Test for OTP
  - Try injection to bypass OTP verification
  - Check for guessable OTP codes
  - Check for the response in order to bypass OTP.
  - Give ' in OTP and check if you can bypass it or not.
- If CSP header blocks the clickjacking attack and origin parameter is present in the original request then this scenario can be bypassed by adding Unicode characters in the value of origin header.
- Use PATCH HTTP header to find information disclosure
- Check whether the application uses any ip address parameter or not. If yes, then decimal IP address can be converted into real ip for information disclosure.
- Imagemagick GIF coder vulnerability leads to memory disclosure
- If the GIT repository file is found on the server, then try to download the entire source code of the website using git-dumper tool.
- Check for the Unsubscribe button
  - Subscribe to email id
  - Unsubscribe and check whether the website confirms first or sends any notification to a user or not.
  - if yes - Not vulnerable
  - if no - Vulnerable (affects availability)
  - If a website has username enumeration issue then it becomes High-Medium level issue.
- Executable download - No secure integrity check
- Reflected file download
- Parameter Pollution - Social Media Sharing Buttons
- Full path disclosure
- Internal Ip disclosure
- Outdated software versions
- Sensitive application data stored unencrypted - Internal storage
- Unsafe Cross-Origin-Resource Sharing
- Directory listing - Non sensitive data exposure.
- Potentially unsafe HTTP method enabled
  - OPTIONS PUT DELETE
- If the server is IIS 7 then test for
  - IIS Short Name scanner
  - HTTP.sys DOS RCE
- WordPress testing
  - enumerate vulnerable plugins
  - enumerate vulnerable themes
  - enumerate email addresses and usernames
  - brute force using custom wordlist using WordPress
- Use Metasploit to find custom exploits
  - use Metasploit --check option to check whether target is exploitable or not
  - remember to give targetURI for the successful exploitation

## 24. Websockets Testing
- Intercepting websockets messaging
- Websockets MITM attempts
- XSS on websockets
- Testing secret header websocket
- Content stealing in websockets
- Token authentication testing in websockets

## 25. JWT Token Testing
- Testing for any leaked secret
- Dictionary attack on token
- Exploiting the ‘None’ algorithm
- Abusing transaction replay
- Abusing key management
- Testing for debug mode
- Testing weak signing key

## 25. API Testing
- Abusing object level authentication
- Abusing weak password/dictionary brute forcing
- Testing for mass management
- Testing for excessive data exposure
- Testing for command injection
- Testing for misconfigured permissions
- Testing for SQL injection
