(function() {
  'use strict';
  module.exports = function(ndx) {
    var LocalStrategy, ObjectID, bcrypt, cookieParser, crypto, flash, generateHash, session, setCookie, validPassword;
    ndx.passport = require('passport');
    flash = require('connect-flash');
    LocalStrategy = require('passport-local').Strategy;
    ObjectID = require('bson-objectid');
    bcrypt = require('bcrypt-nodejs');
    crypto = require('crypto-js');
    session = require('express-session');
    cookieParser = require('cookie-parser');
    setCookie = function(req, res) {
      var cookieText;
      if (req.user) {
        cookieText = req.user._id + '||' + new Date().toString();
        cookieText = crypto.Rabbit.encrypt(cookieText, ndx.settings.SESSION_SECRET).toString();
        return res.cookie('token', cookieText, {
          maxAge: 7 * 24 * 60 * 60 * 1000
        });
      }
    };
    generateHash = function(password) {
      return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
    };
    validPassword = function(password, localPassword) {
      return bcrypt.compareSync(password, localPassword);
    };
    ndx.postAuthenticate = function(req, res, next) {
      console.log('post authenticate');
      setCookie(req, res);
      return res.redirect('/');
    };
    ndx.passport.serializeUser(function(user, done) {
      return done(null, user._id);
    });
    ndx.passport.deserializeUser(function(id, done) {
      return done(null, id);
    });
    ndx.app.use(cookieParser(ndx.settings.SESSION_SECRET)).use(session({
      secret: ndx.settings.SESSION_SECRET,
      saveUninitialized: true,
      resave: true
    })).use(flash()).use(ndx.passport.initialize()).use(ndx.passport.session()).use(function(req, res, next) {
      var bits, d, decrypted, users;
      req.user = null;
      if (req.cookies.token && !ndx.database.maintenance()) {
        decrypted = '';
        try {
          decrypted = crypto.Rabbit.decrypt(req.cookies.token, ndx.settings.SESSION_SECRET).toString(crypto.enc.Utf8);
        } catch (undefined) {}
        if (decrypted.indexOf('||') !== -1) {
          bits = decrypted.split('||');
          if (bits.length === 2) {
            d = new Date(bits[1]);
            if (d.toString() !== 'Invalid Date') {
              users = ndx.database.exec('SELECT * FROM ' + ndx.settings.USER_TABLE + ' WHERE _id=?', [bits[0]]);
              if (users && users.length) {
                req.user = users[0];
                setCookie(req, res);
              }
            }
          }
        }
      }
      return next();
    });
    ndx.app.post('/api/refresh-login', function(req, res) {
      if (req.user) {
        return res.end(JSON.stringify(req.user));
      } else {
        return res.end('error');
      }
    });
    ndx.app.get('/api/logout', function(req, res) {
      res.clearCookie('token');
      res.redirect('/');
    });
    ndx.passport.use('local-signup', new LocalStrategy({
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: true
    }, function(req, email, password, done) {
      var newUser, users;
      users = ndx.database.exec('SELECT * FROM ' + ndx.settings.USER_TABLE + ' WHERE local->email=?', [email]);
      if (users && users.length) {
        return done(null, false, req.flash('message', 'That email is already taken.'));
      } else {
        newUser = {
          _id: ObjectID.generate(),
          email: email,
          local: {
            email: email,
            password: generateHash(password)
          }
        };
        ndx.database.exec('INSERT INTO ' + ndx.settings.USER_TABLE + ' VALUES ?', [newUser]);
        return done(null, newUser);
      }
    }));
    ndx.passport.use('local-login', new LocalStrategy({
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: true
    }, function(req, email, password, done) {
      var users;
      console.log('local-login');
      users = ndx.database.exec('SELECT * FROM ' + ndx.settings.USER_TABLE + ' WHERE local->email=?', [email]);
      if (users && users.length) {
        if (!validPassword(password, users[0].local.password)) {
          return done(null, false, req.flash('message', 'Wrong password'));
        }
        return done(null, users[0]);
      } else {
        console.log('no user');
        return done(null, false, req.flash('message', 'No user found'));
      }
    }));
    ndx.app.post('/api/signup', ndx.passport.authenticate('local-signup', {
      failureRedirect: '/api/badlogin'
    }), ndx.postAuthenticate);
    ndx.app.post('/api/login', ndx.passport.authenticate('local-login', {
      failureRedirect: '/api/badlogin'
    }), ndx.postAuthenticate);
    ndx.app.get('/api/connect/local', function(req, res) {});
    ndx.app.post('/api/connect/local', ndx.passport.authorize('local-signup', {
      failureRedirect: '/api/badlogin'
    }));
    ndx.app.get('/api/unlink/local', function(req, res) {
      var user;
      user = req.user;
      user.local.email = void 0;
      user.local.password = void 0;
      user.save(function(err) {
        res.redirect('/profile');
      });
    });
    return ndx.app.get('/api/badlogin', function(req, res) {
      return res.json({
        error: true,
        message: req.flash('message')
      });
    });
  };

}).call(this);

//# sourceMappingURL=index.js.map
