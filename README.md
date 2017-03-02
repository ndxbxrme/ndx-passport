# ndx-passport 
### provides local user login for [ndx-framework](https://github.com/ndxbxrme/ndx-framework)
install with  
`npm install --save ndx-passport`  
### example

`src/server/app.coffee`  
```coffeescript
require 'ndx-server'
.config
  database: 'db'
.use 'ndx-passport'
.start()
```
`src/client/../login.coffee`  
```coffeescript
#login
$http.post '/api/login',
  email: $scope.email
  password: $scope.password
.then (response) ->
  #logged in
, (err) ->
  #login error
  $scope.message = err.data
#sign up
$http.post '/api/signup',
  email: $scope.email
  password: $scope.password
.then (response) ->
  #logged in
, (err) ->
  #login error
  $scope.message = err.data
```
### environment variables/config options
|environment|config|description|
|-----------|------|-----------|
|USERNAME_FIELD|usernameField|the field passport uses for the username, defaults to `email`|
|PASSWORD_FIELD|passwordField|the field passport uses for the user's password, defaults to `password`|