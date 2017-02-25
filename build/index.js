(function() {
  'use strict';
  module.exports = function(ndx) {
    var LocalStrategy, ObjectID, selectFields;
    ndx.passport = require('passport');
    LocalStrategy = require('passport-local').Strategy;
    ObjectID = require('bson-objectid');
    ndx.passport.serializeUser(function(user, done) {
      return done(null, user._id);
    });
    ndx.passport.deserializeUser(function(id, done) {
      return done(null, id);
    });
    ndx.passport.splitScopes = function(scope) {
      var scopes;
      scopes = scope.replace(/^[ ,]+/, '').replace(/[ ,]+$/, '').split(/[ ,]+/g);
      if (scopes.length < 2) {
        return scopes[0];
      } else {
        return scopes;
      }
    };
    ndx.app.use(ndx.passport.initialize());
    selectFields = function(input, output, fields) {
      var field, inField, results;
      results = [];
      for (field in fields) {
        inField = input[field];
        if (inField) {
          if (Object.prototype.toString.call(inField) === '[object Object]') {
            output[field] = {};
            results.push(selectFields(inField, output[field], fields[field]));
          } else {
            results.push(output[field] = inField);
          }
        } else {
          results.push(void 0);
        }
      }
      return results;
    };
    ndx.app.post('/api/refresh-login', function(req, res) {
      var output;
      if (req.user) {
        output = {};
        if (ndx.settings.publicUser) {
          selectFields(req.user, output, ndx.settings.publicUser);
        } else {
          output = req.user;
        }
        return res.end(JSON.stringify(output));
      } else {
        throw ndx.UNAUTHORIZED;
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
                email: req.user.local.email,
                password: ndx.generateHash(req.body.newPassword)
              }, req.user._id
            ]);
            return res.end('OK');
          } else {
            throw {
              status: 401,
              message: 'Invalid password'
            };
          }
        } else {
          throw {
            status: 401,
            message: 'No local details'
          };
        }
      } else {
        throw {
          status: 401,
          message: 'Not logged in'
        };
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
        ndx.passport.loginMessage = 'That email is already taken.';
        return done(null, false);
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
          ndx.passport.loginMessage = 'Wrong password';
          return done(null, false);
        }
        return done(null, users[0]);
      } else {
        ndx.passport.loginMessage = 'No user found';
        return done(null, false);
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
      throw {
        status: 401,
        message: ndx.passport.loginMessage
      };
    });
  };

}).call(this);

//# sourceMappingURL=index.js.map
