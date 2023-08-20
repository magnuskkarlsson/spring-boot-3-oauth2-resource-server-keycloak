
Resource Owner Password Credentials Grant

https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.2

Access Token Request

     POST /token HTTP/1.1
     Host: server.example.com
     Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
     Content-Type: application/x-www-form-urlencoded

     grant_type=password&username=johndoe&password=A3ddj3w

http://localhost:8180/auth/realms/demo/.well-known/openid-configuration

$ ACCESS_TOKEN=$(curl -s -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -u 'spring-boot3-oauth2-login:jO09Uwhi8oxTL3QnTKtYZ20ByQvB2qA0' \
  http://localhost:8180/auth/realms/demo/protocol/openid-connect/token \
  -d "grant_type=password&username=john&password=changeit" | jq -r .access_token)

---

http://localhost:8080/api/users

$ curl -v -X GET -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:8080/api/users

< HTTP/1.1 302 
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 0
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Location: http://localhost:8080/login


---

https://docs.spring.io/spring-security/reference/servlet/oauth2/client/authorization-grants.html#oauth2Client-jwt-bearer-grant

---























