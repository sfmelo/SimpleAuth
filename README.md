# Setup
1. Run `docker compose up -d db` to run the couchbase server.
2. Go to `localhost:8091` to access the Couchbase server in order to setup the cluster:
    - Click `Setup New Cluster`;
    - Cluster name can be whatever you want, like `SimpleAuthDB`;
    - Admin username and password should be `Administrator` and `password` respecively. If you want to setup different credentials, the username and password on the `config.example.json` should also be changed accordingly. Click `Next: Accept Terms`;
    - Accept terms and conditions and click `Finish With Defaults`
3. Run `docker compose up -d` to run the api. It takes some time to start up full because it takes some time to initialize the database.

# Register user

To register a user, send a POST request to:

`http://localhost:8080/register`

With the following data:
``` json
{
  "username": "sfmelo",
  "email": "sfmelo@realemail.com",
  "password": "password123"
}
```

The response should have a `201 CREATED` status.

# Login
To login, send a POST request to:

`http://localhost:8080/login`

While having the username and password in Basic authentication.

The response should be a token that should be saved:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InNmbWVsbyIsImVtYWlsIjoic2ZtZWxvQHJlYWxlbWFpbC5jb20iLCJleHAiOjE2ODE4NTg0ODR9._0LCEJlPhAZJVUReLpBekR-5a8up4JRBuSKcN_kl784"
}
```

 This token has, by default, 15 minutes before expiring. This time can be changed in the `config.example.json`.

# Verify
To verify if a user is logged in, send a GET request to:

`http://localhost:8080/verify`

While having the token previously obtained in the login section in the Bearer Token. 

If the user is logged in, the response should have a `200 ACCEPTED` status code, otherwise an error is returned.
