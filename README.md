# gin-prisma-backend

1. Register - Assuming your POST /register endpoint expects a JSON body with email and password:
```
curl -X POST \
     -H "Content-Type: application/json" \
     -d '{"email": "test@example.com", "password": "secret"}' \
     http://localhost:8080/register
```
Result:
```
{"message":"User registered successfully","user":{"email":"test@example.com","id":"f766714a-2e4c-4422-98c3-ab876e086391"}
```


2.Login - To log in and obtain a JWT, send a POST /login request with the same credentials:
```
curl -X POST \
     -H "Content-Type: application/json" \
     -d '{"email": "test@example.com", "password": "secret"}' \
     http://localhost:8080/login
```

Example response (if credentials are valid):
```
{
  "token": "your_jwt_token_here"
}
```

3. Profile (Protected Route) - For any protected endpoint like GET /api/profile, include the JWT in the Authorization header as a Bearer token:
```
curl -X GET \
     -H "Authorization: Bearer your_jwt_token_here" \
     http://localhost:8080/api/profile
```
Example response (if token is valid):
```
{
  "id": "some-uuid",
  "email": "test@example.com"
}
```
If the token is invalid or missing, you should get a 401 Unauthorized error.
