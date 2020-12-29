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
