'use strict'
objtrans = require 'objtrans' 

module.exports = (ndx) ->
  ndx.passport = require 'passport'
  LocalStrategy = require('passport-local').Strategy
  usernameField = process.env.USERNAME_FIELD or ndx.settings.USERNAME_FIELD or 'email'
  passwordField = process.env.PASSWORD_FIELD or ndx.settings.PASSWORD_FIELD or 'password'

  if ndx.settings.HAS_FORGOT or process.env.HAS_FORGOT
    require('./forgot') ndx
  
  if ndx.settings.HAS_INVITE or process.env.HAS_INVITE
    require('./invite') ndx

  ndx.passport.serializeUser (user, done) ->
    done null, user[ndx.settings.AUTO_ID]
  ndx.passport.deserializeUser (id, done) ->
    done null, id
  ndx.passport.splitScopes = (scope) ->
    scopes = scope.replace(/^[ ,]+/, '').replace(/[ ,]+$/, '').split(/[ ,]+/g)
    if scopes.length < 2
      return scopes[0]
    else
      return scopes
  
  ndx.app
  .use ndx.passport.initialize()

  ndx.app.post '/api/refresh-login', (req, res) ->
    if ndx.user
      output = {}
      if ndx.settings.PUBLIC_USER
        output = objtrans ndx.user, ndx.settings.PUBLIC_USER
      else
        output = ndx.user
      res.end JSON.stringify output
    else
      if ndx.settings.SOFT_LOGIN
        res.end ''
      else
        throw ndx.UNAUTHORIZED   
        
  ndx.app.get '/api/logout', (req, res) ->
    res.clearCookie 'token'
    ndx.user = null
    res.redirect '/'
    return
  ndx.app.post '/api/update-password', (req, res) ->
    if ndx.user
      if ndx.user.local
        if ndx.validPassword req.body.oldPassword, ndx.user.local.password
          where = {}
          where[ndx.settings.AUTO_ID] = ndx.user[ndx.settings.AUTO_ID]
          ndx.database.update ndx.settings.USER_TABLE,
            local:
              email: ndx.user.local.email
              password: ndx.generateHash req.body.newPassword
          , where, null, true
          res.end 'OK'
        else
          throw
            status: 401
            message: 'Invalid password'
      else
        throw
          status: 401
          message: 'No local details'
    else
      throw
        status: 401
        message: 'Not logged in'
    
    
  ndx.passport.use 'local-signup', new LocalStrategy
    usernameField: usernameField
    passwordField: passwordField
    passReqToCallback: true
  , (req, email, password, done) ->
    ndx.database.select ndx.settings.USER_TABLE,
      where:
        local:
          email: email
    , (users) ->
      if users and users.length
        ndx.passport.loginMessage = 'That email is already taken.'
        return done(null, false)
      else
        newUser = 
          email: email
          local:
            email: email
            password: ndx.generateHash password
        newUser[ndx.settings.AUTO_ID] = ndx.generateID()
        ndx.database.insert ndx.settings.USER_TABLE, newUser, null, true
        ndx.user = newUser
        done null, newUser
    , true 
  ndx.passport.use 'local-login', new LocalStrategy
    usernameField: usernameField
    passwordField: passwordField
    passReqToCallback: true
  , (req, email, password, done) ->
    ndx.database.select ndx.settings.USER_TABLE,
      where:
        local:
          email: email
    , (users) ->
      if users and users.length
        if not ndx.validPassword password, users[0].local.password
          ndx.passport.loginMessage = 'Wrong password'
          return done(null, false)
        ndx.user = users[0]
        return done(null, users[0])
      else
        ndx.passport.loginMessage = 'No user found'
        return done(null, false)
    , true
  ndx.app.post '/api/signup', ndx.passport.authenticate('local-signup', failureRedirect: '/api/badlogin')
  , ndx.postAuthenticate
  ndx.app.post '/api/login', ndx.passport.authenticate('local-login', failureRedirect: '/api/badlogin')
  , ndx.postAuthenticate
  ndx.app.get '/api/connect/local', (req, res) ->
    #send flash message
    return
  ndx.app.post '/api/connect/local', ndx.passport.authorize('local-signup', failureRedirect: '/api/badlogin')
  ndx.app.get '/api/unlink/local', (req, res) ->
    user = ndx.user
    user.local.email = undefined
    user.local.password = undefined
    user.save (err) ->
      res.redirect '/profile'
      return
    return
  ndx.app.get '/api/badlogin', (req, res) ->
    throw
      status: 401
      message: ndx.passport.loginMessage
  