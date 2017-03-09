(function() {
  'use strict';
  module.exports = function(ndx) {
    var LocalStrategy, ObjectID, passwordField, selectFields, usernameField;
    ndx.passport = require('passport');
    LocalStrategy = require('passport-local').Strategy;
    ObjectID = require('bson-objectid');
    usernameField = process.env.USERNAME_FIELD || ndx.settings.USERNAME_FIELD || 'email';
    passwordField = process.env.PASSWORD_FIELD || ndx.settings.PASSWORD_FIELD || 'password';
    ndx.passport.serializeUser(function(user, done) {
      return done(null, user[ndx.settings.AUTO_ID]);
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
      if (ndx.user) {
        output = {};
        if (ndx.settings.PUBLIC_USER) {
          selectFields(ndx.user, output, ndx.settings.PUBLIC_USER);
        } else {
          output = ndx.user;
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
      var where;
      if (ndx.user) {
        if (ndx.user.local) {
          if (ndx.validPassword(req.body.oldPassword, ndx.user.local.password)) {
            where = {};
            where[ndx.settings.AUTO_ID] = ndx.user[ndx.settings.AUTO_ID];
            ndx.database.update(ndx.settings.USER_TABLE, {
              local: {
                email: ndx.user.local.email,
                password: ndx.generateHash(req.body.newPassword)
              }
            }, where);
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
      usernameField: usernameField,
      passwordField: passwordField,
      passReqToCallback: true
    }, function(req, email, password, done) {
      return ndx.database.select(ndx.settings.USER_TABLE, {
        where: {
          local: {
            email: email
          }
        }
      }, function(users) {
        var newUser;
        if (users && users.length) {
          ndx.passport.loginMessage = 'That email is already taken.';
          return done(null, false);
        } else {
          newUser = {
            email: email,
            local: {
              email: email,
              password: ndx.generateHash(password)
            }
          };
          newUser[ndx.settings.AUTO_ID] = ObjectID.generate();
          ndx.database.insert(ndx.settings.USER_TABLE, newUser);
          return done(null, newUser);
        }
      });
    }));
    ndx.passport.use('local-login', new LocalStrategy({
      usernameField: usernameField,
      passwordField: passwordField,
      passReqToCallback: true
    }, function(req, email, password, done) {
      return ndx.database.select(ndx.settings.USER_TABLE, {
        where: {
          local: {
            email: email
          }
        }
      }, function(users) {
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
      });
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
      user = ndx.user;
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
