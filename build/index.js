(function() {
  'use strict';
  var async, objtrans;

  objtrans = require('objtrans');

  async = require('async');

  module.exports = function(ndx) {
    var LocalStrategy, asyncCallback, callbacks, passwordField, syncCallback, usernameField;
    callbacks = {
      login: [],
      logout: [],
      signup: [],
      refreshLogin: [],
      updatePassword: [],
      invited: [],
      inviteAccepted: [],
      inviteUserExists: []
    };
    ndx.passport = require('passport');
    LocalStrategy = require('passport-local').Strategy;
    usernameField = process.env.USERNAME_FIELD || ndx.settings.USERNAME_FIELD || 'email';
    passwordField = process.env.PASSWORD_FIELD || ndx.settings.PASSWORD_FIELD || 'password';
    if (ndx.settings.HAS_FORGOT || process.env.HAS_FORGOT) {
      require('./forgot')(ndx);
    }
    if (ndx.settings.HAS_INVITE || process.env.HAS_INVITE) {
      require('./invite')(ndx);
    }
    syncCallback = function(name, obj, cb) {
      var callback, i, len, ref;
      if (callbacks[name] && callbacks[name].length) {
        ref = callbacks[name];
        for (i = 0, len = ref.length; i < len; i++) {
          callback = ref[i];
          callback(obj);
        }
      }
      return typeof cb === "function" ? cb() : void 0;
    };
    ndx.passport.syncCallback = syncCallback;
    asyncCallback = function(name, obj, cb) {
      var truth;
      truth = false;
      if (callbacks[name] && callbacks[name].length) {
        return async.eachSeries(callbacks[name], function(cbitem, callback) {
          return cbitem(obj, function(result) {
            truth = truth || result;
            return callback();
          });
        }, function() {
          return typeof cb === "function" ? cb(truth) : void 0;
        });
      } else {
        return typeof cb === "function" ? cb(true) : void 0;
      }
    };
    ndx.passport.asyncCallback = asyncCallback;
    ndx.passport.on = function(name, callback) {
      return callbacks[name].push(callback);
    };
    ndx.passport.off = function(name, callback) {
      return callbacks[name].splice(callbacks[name].indexOf(callback), 1);
    };
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
    ndx.passport.fetchByEmail = function(email, done) {
      return ndx.database.select(ndx.settings.USER_TABLE, {
        where: {
          local: {
            email: email
          }
        }
      }, done);
    };
    ndx.passport.createUser = function(email, password) {
      var newUser;
      newUser = {
        email: email,
        local: {
          email: email,
          password: ndx.generateHash(password)
        }
      };
      newUser[ndx.settings.AUTO_ID] = ndx.generateID();
      ndx.database.insert(ndx.settings.USER_TABLE, newUser, null, true);
      return newUser;
    };
    ndx.app.use(ndx.passport.initialize());
    ndx.app.post('/api/refresh-login', function(req, res) {
      var output;
      if (ndx.user) {
        output = {};
        if (ndx.settings.PUBLIC_USER) {
          output = objtrans(ndx.user, ndx.settings.PUBLIC_USER);
        } else {
          output = ndx.user;
        }
        if (req.cookies.impersonate) {
          output.impersonating = true;
        }
        return asyncCallback('refreshLogin', output, function() {
          return res.json(output);
        });
      } else {
        return res.end('');

        /*
        if ndx.settings.SOFT_LOGIN
          res.end ''
        else
          throw ndx.UNAUTHORIZED
         */
      }
    });
    ndx.app.get('/api/logout', function(req, res) {
      syncCallback('logout', ndx.user);
      res.clearCookie('token');
      ndx.user = null;
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
            }, where, null, true);
            syncCallback('updatePassword', ndx.user);
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
      return ndx.passport.fetchByEmail(email, function(users) {
        if (users && users.length) {
          ndx.passport.loginMessage = 'That email is already taken.';
          return done(null, false);
        } else {
          ndx.user = ndx.passport.createUser(email, password);
          if (ndx.auth) {
            ndx.auth.extendUser(ndx.user);
          }
          syncCallback('signup', ndx.user);
          return done(null, ndx.user);
        }
      }, true);
    }));
    ndx.passport.use('local-login', new LocalStrategy({
      usernameField: usernameField,
      passwordField: passwordField,
      passReqToCallback: true
    }, function(req, email, password, done) {
      return ndx.passport.fetchByEmail(email, function(users) {
        if (users && users.length) {
          if (!ndx.validPassword(password, users[0].local.password)) {
            ndx.passport.loginMessage = 'Wrong password';
            return done(null, false);
          }
          ndx.user = users[0];
          if (ndx.auth) {
            ndx.auth.extendUser(ndx.user);
          }
          syncCallback('login', ndx.user);
          return done(null, users[0]);
        } else {
          ndx.passport.loginMessage = 'No user found';
          return done(null, false);
        }
      }, true);
    }));
    ndx.app.post('/api/signup', ndx.passport.authenticate('local-signup', {
      failureRedirect: '/badlogin'
    }), ndx.postAuthenticate);
    ndx.app.post('/api/login', ndx.passport.authenticate('local-login', {
      failureRedirect: '/badlogin'
    }), ndx.postAuthenticate);
    ndx.app.get('/api/connect/local', function(req, res) {});
    ndx.app.post('/api/connect/local', ndx.passport.authorize('local-signup', {
      failureRedirect: '/badlogin'
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
    return ndx.app.get('/badlogin', function(req, res) {
      throw {
        status: 401,
        message: ndx.passport.loginMessage
      };
    });
  };

}).call(this);

//# sourceMappingURL=index.js.map
