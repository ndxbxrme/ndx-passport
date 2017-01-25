'use strict'

module.exports = (ndx) ->
  ndx.passport = require 'passport'
  flash = require 'connect-flash'
  LocalStrategy = require('passport-local').Strategy
  ObjectID = require 'bson-objectid'
  bcrypt = require 'bcrypt-nodejs'
  crypto = require 'crypto-js'
  session = require 'express-session'
  cookieParser = require 'cookie-parser'

  setCookie = (req, res) ->
    if req.user
      cookieText = req.user._id + '||' + new Date().toString()
      cookieText = crypto.Rabbit.encrypt(cookieText, ndx.settings.SESSION_SECRET).toString()
      res.cookie 'token', cookieText, maxAge: 7 * 24 * 60 * 60 * 1000  
  generateHash = (password) ->
    bcrypt.hashSync password, bcrypt.genSaltSync(8), null
  validPassword = (password, localPassword) ->
    bcrypt.compareSync password, localPassword
  ndx.postAuthenticate = (req, res, next) ->
    console.log 'post authenticate'
    setCookie req, res
    res.redirect '/'
  ndx.passport.serializeUser (user, done) ->
    done null, user._id
  ndx.passport.deserializeUser (id, done) ->
    done null, id
  
  ndx.app.use cookieParser ndx.settings.SESSION_SECRET
  .use session
    secret: ndx.settings.SESSION_SECRET
    saveUninitialized: true
    resave: true
  .use flash()
  .use ndx.passport.initialize()
  .use ndx.passport.session()
  .use (req, res, next) ->
    req.user = null
    if req.cookies.token and not ndx.database.maintenance()
      decrypted = ''
      try
        decrypted = crypto.Rabbit.decrypt(req.cookies.token, ndx.settings.SESSION_SECRET).toString(crypto.enc.Utf8)
      if decrypted.indexOf('||') isnt -1
        bits = decrypted.split '||'
        if bits.length is 2
          d = new Date bits[1]
          if d.toString() isnt 'Invalid Date'
            users = ndx.database.exec 'SELECT * FROM ' + ndx.settings.USER_TABLE + ' WHERE _id=?', [bits[0]]
            if users and users.length
              req.user = users[0]
              setCookie req, res
    next()

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
        if validPassword req.body.oldPassword, req.user.local.password
          ndx.database.exec 'UPDATE ' + ndx.settings.USER_TABLE + ' SET local=? WHERE _id=?', [
            {
              email: req.user.email
              password: generateHash req.body.newPassword
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
          password: generateHash password
      ndx.database.exec 'INSERT INTO ' + ndx.settings.USER_TABLE + ' VALUES ?', [newUser]
      done null, newUser
  ndx.passport.use 'local-login', new LocalStrategy
    usernameField: 'email'
    passwordField: 'password'
    passReqToCallback: true
  , (req, email, password, done) ->
    console.log 'local-login'
    users = ndx.database.exec 'SELECT * FROM ' + ndx.settings.USER_TABLE + ' WHERE local->email=?', [email]
    if users and users.length
      if not validPassword password, users[0].local.password
        return done(null, false, req.flash('message', 'Wrong password'))
      return done(null, users[0])
    else
      console.log 'no user'
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
  