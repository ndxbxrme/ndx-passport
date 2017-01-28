(function() {
  'use strict';
  module.exports = function(ndx) {
    var LocalStrategy, ObjectID, bcrypt, crypto, flash, setCookie;
    ndx.passport = require('passport');
    flash = require('connect-flash');
    LocalStrategy = require('passport-local').Strategy;
    ObjectID = require('bson-objectid');
    bcrypt = require('bcrypt-nodejs');
    crypto = require('crypto-js');
    ndx.generateToken = function(userId, ip) {
      var text;
      text = userId + '||' + new Date().toString();
      text = crypto.Rabbit.encrypt(text, ip).toString();
      text = crypto.Rabbit.encrypt(text, ndx.settings.SESSION_SECRET).toString();
      return text;
    };
    setCookie = function(req, res) {
      var cookieText;
      if (req.user) {
        cookieText = ndx.generateToken(req.user._id, req.ip);
        return res.cookie('token', cookieText, {
          maxAge: 7 * 24 * 60 * 60 * 1000
        });
      }
    };
    ndx.generateHash = function(password) {
      return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
    };
    ndx.validPassword = function(password, localPassword) {
      return bcrypt.compareSync(password, localPassword);
    };
    ndx.postAuthenticate = function(req, res, next) {
      setCookie(req, res);
      return res.redirect('/');
    };
    ndx.passport.serializeUser(function(user, done) {
      return done(null, user._id);
    });
    ndx.passport.deserializeUser(function(id, done) {
      return done(null, id);
    });
    ndx.app.use(flash()).use(ndx.passport.initialize()).use('/api/*', function(req, res, next) {
      var bits, credentials, d, decrypted, isCookie, parts, scheme, token, users;
      if (!ndx.database.maintenance()) {
        isCookie = false;
        token = '';
        if (req.cookies && req.cookies.token) {
          token = req.cookies.token;
          isCookie = true;
        } else if (req.headers && req.headers.authorization) {
          parts = req.headers.authorization.split(' ');
          if (parts.length === 2) {
            scheme = parts[0];
            credentials = parts[1];
            if (/^Bearer$/i.test(scheme)) {
              token = credentials;
            }
          }
        }
        decrypted = '';
        try {
          decrypted = crypto.Rabbit.decrypt(token, ndx.settings.SESSION_SECRET).toString(crypto.enc.Utf8);
          if (decrypted) {
            decrypted = crypto.Rabbit.decrypt(decrypted, req.ip).toString(crypto.enc.Utf8);
          }
        } catch (undefined) {}
        if (decrypted.indexOf('||') !== -1) {
          bits = decrypted.split('||');
          if (bits.length === 2) {
            d = new Date(bits[1]);
            if (d.toString() !== 'Invalid Date') {
              users = ndx.database.exec('SELECT * FROM ' + ndx.settings.USER_TABLE + ' WHERE _id=?', [bits[0]]);
              if (users && users.length) {
                if (!req.user) {
                  req.user = {};
                }
                if (Object.prototype.toString.call(req.user) === '[object Object]') {
                  ndx.extend(req.user, users[0]);
                } else {
                  req.user = users[0];
                }
                if (isCookie) {
                  setCookie(req, res);
                }
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
    ndx.app.post('/api/update-password', function(req, res) {
      if (req.user) {
        if (req.user.local) {
          if (ndx.validPassword(req.body.oldPassword, req.user.local.password)) {
            ndx.database.exec('UPDATE ' + ndx.settings.USER_TABLE + ' SET local=? WHERE _id=?', [
              {
                email: req.user.email,
                password: ndx.generateHash(req.body.newPassword)
              }, req.user._id
            ]);
            return res.end('OK');
          } else {
            return res.json({
              error: 'Invalid password'
            });
          }
        } else {
          return res.json({
            error: 'No local details'
          });
        }
      } else {
        return res.json({
          error: 'Not logged in'
        });
      }
    });
    ndx.app.post('/auth/token', function(req, res) {
      var cparts, credentials, decrypted, parts, scheme, token, users;
      token = '';
      if (req.headers && req.headers.authorization) {
        parts = req.headers.authorization.split(' ');
        if (parts.length === 2) {
          scheme = parts[0];
          credentials = parts[1];
          if (/^Basic$/i.test(scheme)) {
            decrypted = new Buffer(credentials, 'base64').toString('utf8');
            cparts = decrypted.split(':');
            if (cparts.length === 2) {
              users = ndx.database.exec('SELECT * FROM ' + ndx.settings.USER_TABLE + ' WHERE local->email=?', [cparts[0]]);
              if (users && users.length) {
                if (ndx.validPassword(cparts[1], users[0].local.password)) {
                  token = ndx.generateToken(users[0]._id, req.ip);
                }
              }
            }
          }
        }
      }
      if (token) {
        return res.json({
          accessToken: token
        });
      } else {
        return res.json({
          error: 'Not authorized'
        });
      }
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
            password: ndx.generateHash(password)
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
      users = ndx.database.exec('SELECT * FROM ' + ndx.settings.USER_TABLE + ' WHERE local->email=?', [email]);
      if (users && users.length) {
        if (!ndx.validPassword(password, users[0].local.password)) {
          return done(null, false, req.flash('message', 'Wrong password'));
        }
        return done(null, users[0]);
      } else {
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
