'use strict'

module.exports = (ndx) ->
  ndx.passport = require 'passport'
  LocalStrategy = require('passport-local').Strategy
  ObjectID = require 'bson-objectid'


  ndx.passport.serializeUser (user, done) ->
    done null, user._id
  ndx.passport.deserializeUser (id, done) ->
    done null, id
  
  ndx.app
  .use ndx.passport.initialize()

  ndx.app.post '/api/refresh-login', (req, res) ->
    if req.user
      res.end JSON.stringify req.user
    else
      res.end 'error'    
  ndx.app.get '/api/logout', (req, res) ->
    res.clearCookie 'token'
    res.redirect '/'
    return
  ndx.app.post '/api/update-password', (req, res) ->
    if req.user
      if req.user.local
        if ndx.validPassword req.body.oldPassword, req.user.local.password
          ndx.database.exec 'UPDATE ' + ndx.settings.USER_TABLE + ' SET local=? WHERE _id=?', [
            {
              email: req.user.email
              password: ndx.generateHash req.body.newPassword
            }
            req.user._id
          ]
          res.end 'OK'
        else
          res.json
            error: 'Invalid password'
      else
        res.json
          error: 'No local details'
    else
      res.json
        error: 'Not logged in'
    
    
  ndx.passport.use 'local-signup', new LocalStrategy
    usernameField: 'email'
    passwordField: 'password'
    passReqToCallback: true
  , (req, email, password, done) ->
    users = ndx.database.exec 'SELECT * FROM ' + ndx.settings.USER_TABLE + ' WHERE local->email=?', [email]
    if users and users.length
      return done(null, false, req.flash('message', 'That email is already taken.'))
    else
      newUser = 
        _id: ObjectID.generate()
        email: email
        local:
          email: email
          password: ndx.generateHash password
      ndx.database.exec 'INSERT INTO ' + ndx.settings.USER_TABLE + ' VALUES ?', [newUser]
      done null, newUser
  ndx.passport.use 'local-login', new LocalStrategy
    usernameField: 'email'
    passwordField: 'password'
    passReqToCallback: true
  , (req, email, password, done) ->
    users = ndx.database.exec 'SELECT * FROM ' + ndx.settings.USER_TABLE + ' WHERE local->email=?', [email]
    if users and users.length
      if not ndx.validPassword password, users[0].local.password
        return done(null, false, req.flash('message', 'Wrong password'))
      return done(null, users[0])
    else
      return done(null, false, req.flash('message', 'No user found'))
  ndx.app.post '/api/signup', ndx.passport.authenticate('local-signup', failureRedirect: '/api/badlogin')
  , ndx.postAuthenticate
  ndx.app.post '/api/login', ndx.passport.authenticate('local-login', failureRedirect: '/api/badlogin')
  , ndx.postAuthenticate
  ndx.app.get '/api/connect/local', (req, res) ->
    #send flash message
    return
  ndx.app.post '/api/connect/local', ndx.passport.authorize('local-signup', failureRedirect: '/api/badlogin')
  ndx.app.get '/api/unlink/local', (req, res) ->
    user = req.user
    user.local.email = undefined
    user.local.password = undefined
    user.save (err) ->
      res.redirect '/profile'
      return
    return
  ndx.app.get '/api/badlogin', (req, res) ->
    res.json
      error: true
      message: req.flash 'message'
  