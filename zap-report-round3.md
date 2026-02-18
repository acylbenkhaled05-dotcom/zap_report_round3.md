# ZAP by Checkmarx Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 1 |
| Medium | 3 |
| Low | 4 |
| Informational | 4 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| High | Exceeded High |  | Percentage of memory used | 95    |
| Low | Warning |  | ZAP errors logged - see the zap.log file for details | 121    |
| Low | Warning |  | ZAP warnings logged - see the zap.log file for details | 42 211    |
| Info | Informational | http://localhost:8003 | Percentage of responses with status code 2xx | 43 % |
| Info | Informational | http://localhost:8003 | Percentage of responses with status code 3xx | 15 % |
| Info | Exceeded Low | http://localhost:8003 | Percentage of responses with status code 4xx | 38 % |
| Info | Informational | http://localhost:8003 | Percentage of responses with status code 5xx | 2 % |
| Info | Informational | http://localhost:8003 | Percentage of endpoints with content type application/javascript | 13 % |
| Info | Informational | http://localhost:8003 | Percentage of endpoints with content type image/png | 4 % |
| Info | Informational | http://localhost:8003 | Percentage of endpoints with content type text/css | 4 % |
| Info | Informational | http://localhost:8003 | Percentage of endpoints with content type text/html | 22 % |
| Info | Informational | http://localhost:8003 | Percentage of endpoints with content type text/plain | 45 % |
| Info | Informational | http://localhost:8003 | Percentage of endpoints with method GET | 90 % |
| Info | Informational | http://localhost:8003 | Percentage of endpoints with method POST | 9 % |
| Info | Informational | http://localhost:8003 | Count of total endpoints | 22    |
| Info | Informational | http://localhost:8003 | Percentage of slow responses | 3 % |
| Info | Informational | https://content-signature-2.cdn.mozilla.net | Percentage of responses with status code 2xx | 100 % |
| Info | Informational | https://content-signature-2.cdn.mozilla.net | Percentage of endpoints with content type binary/octet-stream | 100 % |
| Info | Informational | https://content-signature-2.cdn.mozilla.net | Percentage of endpoints with method GET | 100 % |
| Info | Informational | https://content-signature-2.cdn.mozilla.net | Count of total endpoints | 1    |
| Info | Informational | https://content-signature-2.cdn.mozilla.net | Percentage of slow responses | 50 % |
| Info | Informational | https://firefox-settings-attachments.cdn.mozilla.net | Percentage of responses with status code 2xx | 100 % |
| Info | Informational | https://firefox-settings-attachments.cdn.mozilla.net | Percentage of endpoints with content type application/octet-stream | 6 % |
| Info | Informational | https://firefox-settings-attachments.cdn.mozilla.net | Percentage of endpoints with content type text/plain | 93 % |
| Info | Informational | https://firefox-settings-attachments.cdn.mozilla.net | Percentage of endpoints with method GET | 100 % |
| Info | Informational | https://firefox-settings-attachments.cdn.mozilla.net | Count of total endpoints | 16    |
| Info | Informational | https://firefox-settings-attachments.cdn.mozilla.net | Percentage of slow responses | 38 % |
| Info | Informational | https://firefox.settings.services.mozilla.com | Percentage of responses with status code 2xx | 100 % |
| Info | Informational | https://firefox.settings.services.mozilla.com | Percentage of endpoints with content type application/json | 100 % |
| Info | Informational | https://firefox.settings.services.mozilla.com | Percentage of endpoints with method GET | 100 % |
| Info | Informational | https://firefox.settings.services.mozilla.com | Count of total endpoints | 5    |
| Info | Informational | https://firefox.settings.services.mozilla.com | Percentage of slow responses | 22 % |




## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| SQL Injection | High | 23 |
| Absence of Anti-CSRF Tokens | Medium | 1 |
| Cross-Domain Misconfiguration | Medium | 5 |
| Format String Error | Medium | 23 |
| Server Leaks Version Information via "Server" HTTP Response Header Field | Low | 1 |
| Strict-Transport-Security Header Not Set | Low | Systemic |
| Timestamp Disclosure - Unix | Low | Systemic |
| X-Content-Type-Options Header Missing | Low | Systemic |
| Authentication Request Identified | Informational | 1 |
| Re-examine Cache-control Directives | Informational | Systemic |
| Retrieved from Cache | Informational | Systemic |
| User Agent Fuzzer | Informational | Systemic |




## Alert Detail



### [ SQL Injection ](https://www.zaproxy.org/docs/alerts/40018/)



##### High (Low)

### Description

SQL injection may be possible.

* URL: http://localhost:8003
  * Node Name: `http://localhost:8003`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/
  * Node Name: `http://localhost:8003/`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/cookiepolicy
  * Node Name: `http://localhost:8003/cookiepolicy`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/favicon.ico
  * Node Name: `http://localhost:8003/favicon.ico`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/login
  * Node Name: `http://localhost:8003/login`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/privacypolicy
  * Node Name: `http://localhost:8003/privacypolicy`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/register
  * Node Name: `http://localhost:8003/register`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/reservation
  * Node Name: `http://localhost:8003/reservation`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/resources
  * Node Name: `http://localhost:8003/resources`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/robots.txt
  * Node Name: `http://localhost:8003/robots.txt`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/sitemap.xml
  * Node Name: `http://localhost:8003/sitemap.xml`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/static
  * Node Name: `http://localhost:8003/static`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/static/
  * Node Name: `http://localhost:8003/static/`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/static/footer.html
  * Node Name: `http://localhost:8003/static/footer.html`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/static/footer.js
  * Node Name: `http://localhost:8003/static/footer.js`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/static/index.js
  * Node Name: `http://localhost:8003/static/index.js`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/static/logo.png
  * Node Name: `http://localhost:8003/static/logo.png`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/static/status.js
  * Node Name: `http://localhost:8003/static/status.js`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/static/tailwind.css
  * Node Name: `http://localhost:8003/static/tailwind.css`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/status.html%3Fmessage=%253Cstrong%253EValidation%2520Error(s&29%253A%253C%252Fstrong%253E%253Cbr%253EInvalid%2520email%2520or%2520password!&status=failed
  * Node Name: `http://localhost:8003/status.html (message,status)`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/terms
  * Node Name: `http://localhost:8003/terms`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/login
  * Node Name: `http://localhost:8003/login ()(csrf_token,password,username)`
  * Method: `POST`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://localhost:8003/register
  * Node Name: `http://localhost:8003/register ()(birthdate,password,role,username)`
  * Method: `POST`
  * Parameter: `host`
  * Attack: `localhost:8003'`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``


Instances: 23

### Solution

Do not trust client side input, even if there is client side validation in place.
In general, type check all data on the server side.
If the application uses JDBC, use PreparedStatement or CallableStatement, with parameters passed by '?'
If the application uses ASP, use ADO Command Objects with strong type checking and parameterized queries.
If database Stored Procedures can be used, use them.
Do *not* concatenate strings into queries in the stored procedure, or use 'exec', 'exec immediate', or equivalent functionality!
Do not create dynamic SQL queries using simple string concatenation.
Escape all data received from the client.
Apply an 'allow list' of allowed characters, or a 'deny list' of disallowed characters in user input.
Apply the principle of least privilege by using the least privileged database user possible.
In particular, avoid using the 'sa' or 'db-owner' database users. This does not eliminate SQL injection, but minimizes its impact.
Grant the minimum database access that is necessary for the application.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)


#### CWE Id: [ 89 ](https://cwe.mitre.org/data/definitions/89.html)


#### WASC Id: 19

#### Source ID: 1

### [ Absence of Anti-CSRF Tokens ](https://www.zaproxy.org/docs/alerts/10202/)



##### Medium (Low)

### Description

No Anti-CSRF tokens were found in a HTML submission form.
A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf.

CSRF attacks are effective in a number of situations, including:
    * The victim has an active session on the target site.
    * The victim is authenticated via HTTP auth on the target site.
    * The victim is on the same local network as the target site.

CSRF has primarily been used to perform an action against a target site using the victim's privileges, but recent techniques have been discovered to disclose information by gaining access to the response. The risk of information disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.

* URL: http://localhost:8003/register
  * Node Name: `http://localhost:8003/register`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form action="/register" method="POST">`
  * Other Info: `No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token, _csrfToken] was found in the following HTML form: [Form 1: "birthdate" "password" "username" ].`


Instances: 1

### Solution

Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
For example, use anti-CSRF packages such as the OWASP CSRFGuard.

Phase: Implementation
Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script.

Phase: Architecture and Design
Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).
Note that this can be bypassed using XSS.

Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.
Note that this can be bypassed using XSS.

Use the ESAPI Session Management control.
This control includes a component for CSRF.

Do not use the GET method for any request that triggers a state change.

Phase: Implementation
Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* [ https://cwe.mitre.org/data/definitions/352.html ](https://cwe.mitre.org/data/definitions/352.html)


#### CWE Id: [ 352 ](https://cwe.mitre.org/data/definitions/352.html)


#### WASC Id: 9

#### Source ID: 3

### [ Cross-Domain Misconfiguration ](https://www.zaproxy.org/docs/alerts/10098/)



##### Medium (Medium)

### Description

Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

* URL: https://firefox.settings.services.mozilla.com/v1/
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `access-control-allow-origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons-bloomfilters/changeset%3F_expected=1771396598516&_since=%25221764570990070%2522
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons-bloomfilters/changeset (_expected,_since)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `access-control-allow-origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/mfcdm-origins-list/changeset%3F_expected=1750871406038
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/mfcdm-origins-list/changeset (_expected)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `access-control-allow-origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset%3F_expected=0
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset (_expected)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `access-control-allow-origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset%3Fcollection=mfcdm-origins-list&bucket=main&_expected=0
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset (_expected,bucket,collection)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `access-control-allow-origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`


Instances: 5

### Solution

Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

### Reference


* [ https://vulncat.fortify.com/en/detail?category=HTML5&subcategory=Overly%20Permissive%20CORS%20Policy ](https://vulncat.fortify.com/en/detail?category=HTML5&subcategory=Overly%20Permissive%20CORS%20Policy)


#### CWE Id: [ 264 ](https://cwe.mitre.org/data/definitions/264.html)


#### WASC Id: 14

#### Source ID: 3

### [ Format String Error ](https://www.zaproxy.org/docs/alerts/30002/)



##### Medium (Medium)

### Description

A Format String error occurs when the submitted data of an input string is evaluated as a command by the application.

* URL: http://localhost:8003
  * Node Name: `http://localhost:8003`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/
  * Node Name: `http://localhost:8003/`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/cookiepolicy
  * Node Name: `http://localhost:8003/cookiepolicy`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/favicon.ico
  * Node Name: `http://localhost:8003/favicon.ico`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/login
  * Node Name: `http://localhost:8003/login`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/privacypolicy
  * Node Name: `http://localhost:8003/privacypolicy`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/register
  * Node Name: `http://localhost:8003/register`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/reservation
  * Node Name: `http://localhost:8003/reservation`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/resources
  * Node Name: `http://localhost:8003/resources`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/robots.txt
  * Node Name: `http://localhost:8003/robots.txt`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/sitemap.xml
  * Node Name: `http://localhost:8003/sitemap.xml`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/static
  * Node Name: `http://localhost:8003/static`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/static/
  * Node Name: `http://localhost:8003/static/`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/static/footer.html
  * Node Name: `http://localhost:8003/static/footer.html`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/static/footer.js
  * Node Name: `http://localhost:8003/static/footer.js`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/static/index.js
  * Node Name: `http://localhost:8003/static/index.js`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/static/logo.png
  * Node Name: `http://localhost:8003/static/logo.png`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/static/status.js
  * Node Name: `http://localhost:8003/static/status.js`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/static/tailwind.css
  * Node Name: `http://localhost:8003/static/tailwind.css`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/status.html%3Fmessage=%253Cstrong%253EValidation%2520Error(s&29%253A%253C%252Fstrong%253E%253Cbr%253EInvalid%2520email%2520or%2520password!&status=failed
  * Node Name: `http://localhost:8003/status.html (message,status)`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/terms
  * Node Name: `http://localhost:8003/terms`
  * Method: `GET`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/login
  * Node Name: `http://localhost:8003/login ()(csrf_token,password,username)`
  * Method: `POST`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`
* URL: http://localhost:8003/register
  * Node Name: `http://localhost:8003/register ()(birthdate,password,role,username)`
  * Method: `POST`
  * Parameter: `host`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`


Instances: 23

### Solution

Rewrite the background program using proper deletion of bad character strings. This will require a recompile of the background executable.

### Reference


* [ https://owasp.org/www-community/attacks/Format_string_attack ](https://owasp.org/www-community/attacks/Format_string_attack)


#### CWE Id: [ 134 ](https://cwe.mitre.org/data/definitions/134.html)


#### WASC Id: 6

#### Source ID: 1

### [ Server Leaks Version Information via "Server" HTTP Response Header Field ](https://www.zaproxy.org/docs/alerts/10036/)



##### Low (High)

### Description

The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.

* URL: https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2026-03-28-10-13-31.chain
  * Node Name: `https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2026-03-28-10-13-31.chain`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `AmazonS3`
  * Other Info: ``


Instances: 1

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.

### Reference


* [ https://httpd.apache.org/docs/current/mod/core.html#servertokens ](https://httpd.apache.org/docs/current/mod/core.html#servertokens)
* [ https://learn.microsoft.com/en-us/previous-versions/msp-n-p/ff648552(v=pandp.10) ](https://learn.microsoft.com/en-us/previous-versions/msp-n-p/ff648552(v=pandp.10))
* [ https://www.troyhunt.com/shhh-dont-let-your-response-headers/ ](https://www.troyhunt.com/shhh-dont-let-your-response-headers/)


#### CWE Id: [ 497 ](https://cwe.mitre.org/data/definitions/497.html)


#### WASC Id: 13

#### Source ID: 3

### [ Strict-Transport-Security Header Not Set ](https://www.zaproxy.org/docs/alerts/10035/)



##### Low (High)

### Description

HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying user agents (such as a web browser) are to interact with it using only secure HTTPS connections (i.e. HTTP layered over TLS/SSL). HSTS is an IETF standards track protocol and is specified in RFC 6797.

* URL: https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2026-03-28-10-13-31.chain
  * Node Name: `https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2026-03-28-10-13-31.chain`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/47c73e1a-0449-4cac-adcb-929ce1d88644
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/47c73e1a-0449-4cac-adcb-929ce1d88644`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/a2d53d85-511b-4644-930b-891db71f2cc8
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/a2d53d85-511b-4644-930b-891db71f2cc8`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/bee937c5-37f9-46b7-b7f8-4c284e81051c
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/bee937c5-37f9-46b7-b7f8-4c284e81051c`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/c93ceb0e-0ed0-43c4-bc87-c8abeca12ca6
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/c93ceb0e-0ed0-43c4-bc87-c8abeca12ca6`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: Systemic


### Solution

Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)
* [ https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security ](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)
* [ https://caniuse.com/stricttransportsecurity ](https://caniuse.com/stricttransportsecurity)
* [ https://datatracker.ietf.org/doc/html/rfc6797 ](https://datatracker.ietf.org/doc/html/rfc6797)


#### CWE Id: [ 319 ](https://cwe.mitre.org/data/definitions/319.html)


#### WASC Id: 15

#### Source ID: 3

### [ Timestamp Disclosure - Unix ](https://www.zaproxy.org/docs/alerts/10096/)



##### Low (Low)

### Description

A timestamp was disclosed by the application/web server. - Unix

* URL: https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1703946492`
  * Other Info: `1703946492, which evaluates to: 2023-12-30 16:28:12.`
* URL: https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1763601002`
  * Other Info: `1763601002, which evaluates to: 2025-11-20 03:10:02.`
* URL: https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1773959826`
  * Other Info: `1773959826, which evaluates to: 2026-03-20 00:37:06.`
* URL: https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1827377968`
  * Other Info: `1827377968, which evaluates to: 2027-11-28 06:59:28.`
* URL: https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1889814595`
  * Other Info: `1889814595, which evaluates to: 2029-11-19 22:29:55.`

Instances: Systemic


### Solution

Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.

### Reference


* [ https://cwe.mitre.org/data/definitions/200.html ](https://cwe.mitre.org/data/definitions/200.html)


#### CWE Id: [ 497 ](https://cwe.mitre.org/data/definitions/497.html)


#### WASC Id: 13

#### Source ID: 3

### [ X-Content-Type-Options Header Missing ](https://www.zaproxy.org/docs/alerts/10021/)



##### Low (Medium)

### Description

The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

* URL: https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2026-03-28-10-13-31.chain
  * Node Name: `https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2026-03-28-10-13-31.chain`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/47c73e1a-0449-4cac-adcb-929ce1d88644
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/47c73e1a-0449-4cac-adcb-929ce1d88644`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/a2d53d85-511b-4644-930b-891db71f2cc8
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/a2d53d85-511b-4644-930b-891db71f2cc8`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/bee937c5-37f9-46b7-b7f8-4c284e81051c
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/bee937c5-37f9-46b7-b7f8-4c284e81051c`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/c93ceb0e-0ed0-43c4-bc87-c8abeca12ca6
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/c93ceb0e-0ed0-43c4-bc87-c8abeca12ca6`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`

Instances: Systemic


### Solution

Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

### Reference


* [ https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85) ](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85))
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (High)

### Description

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: http://localhost:8003/login
  * Node Name: `http://localhost:8003/login ()(csrf_token,password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=test@test.com
passwordParam=password
referer=http://localhost:8003/login
csrfToken=csrf_token`


Instances: 1

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ Re-examine Cache-control Directives ](https://www.zaproxy.org/docs/alerts/10015/)



##### Informational (Low)

### Description

The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content. For static assets like css, js, or image files this might be intended, however, the resources should be reviewed to ensure that no sensitive content will be cached.

* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/47c73e1a-0449-4cac-adcb-929ce1d88644
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/47c73e1a-0449-4cac-adcb-929ce1d88644`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=3600`
  * Other Info: ``
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/a2d53d85-511b-4644-930b-891db71f2cc8
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/a2d53d85-511b-4644-930b-891db71f2cc8`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=3600`
  * Other Info: ``
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/bee937c5-37f9-46b7-b7f8-4c284e81051c
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/bee937c5-37f9-46b7-b7f8-4c284e81051c`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=3600`
  * Other Info: ``
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/c93ceb0e-0ed0-43c4-bc87-c8abeca12ca6
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/c93ceb0e-0ed0-43c4-bc87-c8abeca12ca6`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=3600`
  * Other Info: ``
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/ff42caea-2576-49ec-8bed-38bd01e50118
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/ff42caea-2576-49ec-8bed-38bd01e50118`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `public, max-age=3600`
  * Other Info: ``
* URL: https://firefox.settings.services.mozilla.com/v1/
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `max-age=3600`
  * Other Info: ``
* URL: https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons-bloomfilters/changeset%3F_expected=1771396598516&_since=%25221764570990070%2522
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons-bloomfilters/changeset (_expected,_since)`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `max-age=3600`
  * Other Info: ``
* URL: https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/mfcdm-origins-list/changeset%3F_expected=1750871406038
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/mfcdm-origins-list/changeset (_expected)`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `max-age=3600`
  * Other Info: ``
* URL: https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset%3F_expected=0
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset (_expected)`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `max-age=3600`
  * Other Info: ``
* URL: https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset%3Fcollection=mfcdm-origins-list&bucket=main&_expected=0
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset (_expected,bucket,collection)`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `max-age=3600`
  * Other Info: ``

Instances: Systemic


### Solution

For secure content, ensure the cache-control HTTP header is set with "no-cache, no-store, must-revalidate". If an asset should be cached consider setting the directives "public, max-age, immutable".

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching ](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching)
* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control)
* [ https://grayduck.mn/2021/09/13/cache-control-recommendations/ ](https://grayduck.mn/2021/09/13/cache-control-recommendations/)


#### CWE Id: [ 525 ](https://cwe.mitre.org/data/definitions/525.html)


#### WASC Id: 13

#### Source ID: 3

### [ Retrieved from Cache ](https://www.zaproxy.org/docs/alerts/10050/)



##### Informational (Medium)

### Description

The content was retrieved from a shared cache. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.

* URL: https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/bundles/startup.json.mozlz4`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HIT`
  * Other Info: ``
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/47c73e1a-0449-4cac-adcb-929ce1d88644
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/47c73e1a-0449-4cac-adcb-929ce1d88644`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HIT`
  * Other Info: ``
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/a2d53d85-511b-4644-930b-891db71f2cc8
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/a2d53d85-511b-4644-930b-891db71f2cc8`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HIT`
  * Other Info: ``
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/bee937c5-37f9-46b7-b7f8-4c284e81051c
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/bee937c5-37f9-46b7-b7f8-4c284e81051c`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HIT`
  * Other Info: ``
* URL: https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/c93ceb0e-0ed0-43c4-bc87-c8abeca12ca6
  * Node Name: `https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/tracking-protection-lists/c93ceb0e-0ed0-43c4-bc87-c8abeca12ca6`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HIT`
  * Other Info: ``
* URL: https://firefox.settings.services.mozilla.com/v1/
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HIT`
  * Other Info: ``
* URL: https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons-bloomfilters/changeset%3F_expected=1771396598516&_since=%25221764570990070%2522
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons-bloomfilters/changeset (_expected,_since)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HIT`
  * Other Info: ``
* URL: https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/mfcdm-origins-list/changeset%3F_expected=1750871406038
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/mfcdm-origins-list/changeset (_expected)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HIT`
  * Other Info: ``
* URL: https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset%3F_expected=0
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset (_expected)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HIT`
  * Other Info: ``
* URL: https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset%3Fcollection=mfcdm-origins-list&bucket=main&_expected=0
  * Node Name: `https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset (_expected,bucket,collection)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HIT`
  * Other Info: ``
* URL: https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2026-03-28-10-13-31.chain
  * Node Name: `https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2026-03-28-10-13-31.chain`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 1489`
  * Other Info: `The presence of the 'Age' header indicates that a HTTP/1.1 compliant caching server is in use.`
* URL: https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2026-03-28-10-13-31.chain
  * Node Name: `https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2026-03-28-10-13-31.chain`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 3394`
  * Other Info: `The presence of the 'Age' header indicates that a HTTP/1.1 compliant caching server is in use.`
* URL: https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2026-03-28-10-13-31.chain
  * Node Name: `https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2026-03-28-10-13-31.chain`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 3567`
  * Other Info: `The presence of the 'Age' header indicates that a HTTP/1.1 compliant caching server is in use.`
* URL: https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2026-03-28-10-13-31.chain
  * Node Name: `https://content-signature-2.cdn.mozilla.net/g/chains/202402/remote-settings.content-signature.mozilla.org-2026-03-28-10-13-31.chain`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 535`
  * Other Info: `The presence of the 'Age' header indicates that a HTTP/1.1 compliant caching server is in use.`

Instances: Systemic


### Solution

Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Expires: 0
This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request.

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.rfc-editor.org/rfc/rfc9110.html ](https://www.rfc-editor.org/rfc/rfc9110.html)


#### CWE Id: [ 525 ](https://cwe.mitre.org/data/definitions/525.html)


#### Source ID: 3

### [ User Agent Fuzzer ](https://www.zaproxy.org/docs/alerts/10104/)



##### Informational (Medium)

### Description

Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.

* URL: http://localhost:8003/login
  * Node Name: `http://localhost:8003/login ()(csrf_token,password,username)`
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:8003/login
  * Node Name: `http://localhost:8003/login ()(csrf_token,password,username)`
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:8003/register
  * Node Name: `http://localhost:8003/register ()(birthdate,password,role,username)`
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:8003/register
  * Node Name: `http://localhost:8003/register ()(birthdate,password,role,username)`
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://localhost:8003/register
  * Node Name: `http://localhost:8003/register ()(birthdate,password,role,username)`
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``

Instances: Systemic


### Solution



### Reference


* [ https://owasp.org/wstg ](https://owasp.org/wstg)



#### Source ID: 1


