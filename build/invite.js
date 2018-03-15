(function() {
  'use strict';
  module.exports = function(ndx) {
    var b64Enc, tokenFromUser, userFromToken;
    if (ndx.settings.HAS_INVITE || process.env.HAS_INVITE) {
      ndx.passport.inviteTokenHours = 7 * 24;
      if (typeof btoa === 'undefined') {
        global.btoa = function(str) {
          return new Buffer(str).toString('base64');
        };
      }
      if (typeof atob === 'undefined') {
        global.atob = function(b64Encoded) {
          return new Buffer(b64Encoded, 'base64').toString();
        };
      }
      b64Enc = function(str) {
        return btoa;
      };
      userFromToken = function(token, cb) {
        var parseToken;
        parseToken = function(token, cb) {
          var e, error;
          try {
            return cb(null, JSON.parse(ndx.parseToken(atob(decodeURIComponent(token)), true)));
          } catch (error) {
            e = error;
            return cb(e);
          }
        };
        if (ndx.shortToken) {
          return ndx.shortToken.fetch(token, function(err, _token) {
            if (err) {
              return cb(err);
            } else {
              return parseToken(_token, cb);
            }
          });
        } else {
          return parseToken(token, cb);
        }
      };
      tokenFromUser = function(user, cb) {
        var token;
        token = encodeURIComponent(btoa(ndx.generateToken(JSON.stringify(user), null, ndx.passport.inviteTokenHours, true)));
        if (ndx.shortToken) {
          return ndx.shortToken.generate(token, function(shortToken) {
            return cb(shortToken);
          });
        } else {
          return cb(token);
        }
      };
      ndx.invite = {
        fetchTemplate: function(data, cb) {
          return cb({
            subject: "You have been invited",
            body: 'h1 invite\np\n  a(href="#{code}")= code',
            from: "System"
          });
        },
        users: ['admin', 'superadmin'],
        userFromToken: userFromToken,
        tokenFromUser: tokenFromUser
      };
      ndx.app.post('/invite/accept', function(req, res, next) {
        return userFromToken(req.body.code, function(err, user) {
          if (err) {
            return next(err);
          } else {
            return ndx.database.select(ndx.settings.USER_TABLE, {
              where: {
                local: {
                  email: user.local.email
                }
              }
            }, function(users) {
              if (users && users.length) {
                return next('User already exists');
              }
              delete req.body.user.roles;
              delete req.body.user.type;
              ndx.extend(user, req.body.user);
              user.local.password = ndx.generateHash(user.local.password);
              return ndx.database.insert(ndx.settings.USER_TABLE, user, function() {
                if (ndx.shortToken) {
                  ndx.shortToken.remove(req.body.code);
                }
                ndx.passport.syncCallback('inviteAccepted', {
                  obj: user,
                  code: req.body.code
                });
                return res.end('OK');
              });
            });
          }
        });
      });
      ndx.app.get('/invite/user/:code', function(req, res, next) {
        return userFromToken(req.params.code, function(err, user) {
          if (err) {
            return next(err);
          }
          return ndx.passport.fetchByEmail(user.local.email, function(users) {
            if (users && users.length) {
              user.$exists = true;
            }
            return res.json(user);
          });
        });
      });
      return ndx.app.post('/api/get-invite-code', ndx.authenticate(), function(req, res, next) {
        delete req.body._id;
        return (function(user) {
          return ndx.passport.fetchByEmail(req.body.local.email, function(users) {
            var obj;
            if (users && users.length) {
              obj = {
                error: 'User already exists',
                dbUser: users[0],
                newUser: req.body
              };
              return ndx.passport.asyncCallback('inviteUserExists', obj, function(result) {
                if (obj.error) {
                  return next(obj.error);
                } else {
                  return res.json(obj);
                }
              });
            } else {
              return tokenFromUser(req.body, function(token) {
                var host;
                host = process.env.HOST || ndx.settings.HOST || (req.protocol + "://" + req.hostname);
                return ndx.invite.fetchTemplate(req.body, function(inviteTemplate) {
                  if (ndx.email) {
                    ndx.email.send({
                      to: req.body.local.email,
                      from: inviteTemplate.from,
                      subject: inviteTemplate.subject,
                      body: inviteTemplate.body,
                      data: req.body,
                      code: host + "/invite/" + token
                    });
                  }
                  ndx.passport.syncCallback('invited', {
                    user: user,
                    obj: req.body,
                    code: token,
                    expires: new Date().valueOf() + (ndx.passport.inviteTokenHours * 60 * 60 * 1000)
                  });
                  return res.end(host + "/invite/" + token);
                });
              });
            }
          });
        })(ndx.user);
      });
    }
  };

}).call(this);

//# sourceMappingURL=invite.js.map
