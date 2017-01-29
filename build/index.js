(function() {
  'use strict';
  module.exports = function(ndx) {
    var LocalStrategy, ObjectID;
    ndx.passport = require('passport');
    LocalStrategy = require('passport-local').Strategy;
    ObjectID = require('bson-objectid');
    ndx.passport.serializeUser(function(user, done) {
      return done(null, user._id);
    });
    ndx.passport.deserializeUser(function(id, done) {
      return done(null, id);
    });
    ndx.app.use(ndx.passport.initialize());
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
                email: req.user.local.email,
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
