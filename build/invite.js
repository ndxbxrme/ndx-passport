(function() {
  'use strict';
  module.exports = function(ndx) {
    var tokenFromUser, userFromToken;
    if (ndx.settings.HAS_INVITE || process.env.HAS_INVITE) {
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
        token = encodeURIComponent(btoa(ndx.generateToken(JSON.stringify(user), null, 4 * 24, true)));
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
        users: ['admin', 'superadmin']
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
              ndx.database.insert(ndx.settings.USER_TABLE, user);
              return res.end('OK');
            });
          }
        });
      });
      ndx.app.get('/invite/:code', function(req, res, next) {
        return userFromToken(req.params.code, function(err, user) {
          if (err) {
            return next(err);
          }
          return res.redirect("/invited?" + (encodeURIComponent(req.params.code)) + "++" + (btoa(JSON.stringify(user))));
        });
      });
      return ndx.app.post('/api/get-invite-code', ndx.authenticate(ndx.invite.users), function(req, res, next) {
        return ndx.database.select(ndx.settings.USER_TABLE, {
          where: {
            local: {
              email: req.body.local.email
            }
          }
        }, function(users) {
          if (users && users.length) {
            return next('User already exists');
          }
          return tokenFromUser(req.body, function(token) {
            var host;
            host = process.env.HOST || ndx.settings.HOST || (req.protocol + "://" + req.hostname);
            token = host + "/invite/" + token;
            return ndx.invite.fetchTemplate(req.body, function(inviteTemplate) {
              if (ndx.email) {
                ndx.email.send({
                  to: req.body.local.email,
                  from: inviteTemplate.from,
                  subject: inviteTemplate.subject,
                  body: inviteTemplate.body,
                  code: token
                });
              }
              return res.end(token);
            });
          });
        });
      });
    }
  };

}).call(this);

//# sourceMappingURL=invite.js.map
