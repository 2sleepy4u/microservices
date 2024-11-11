## Authentication service

This is the main multi-app authentication service written in Rust.  

It only expose 4 endpoints:
- ping: for healthchecks
- register: a protected endpoint to register new users
- login: an endpoint to retrive the auth token
- verify: an endpoint to verify remotely the auth token
More documentation about the endpoints can be found in the OpenAPI .json or using the integrated swagger UI. 

## How it works?

### Token

Token is signed with private key only available to this service.  
The public key can be distributed and it is used to verify the token.  

### Authorization

Authorization is centralized within this service. This service uses a role based authorization system.  
Inside **Permission** table, roles are created, assigned then within the **UsersPermissions** table.  
It will be the targeted app responsability to map the roles to actual authorization logic.  


## TODO
SSL/TLS?
