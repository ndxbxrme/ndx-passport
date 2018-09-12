(function() {
  'use strict';
  module.exports = function(ndx) {
    if (ndx.settings.HAS_FORGOT || process.env.HAS_FORGOT) {
      ndx.forgot = {
        fetchTemplate: function(data, cb) {
          return cb({
            subject: "forgot password",
            body: 'h1 forgot password\np\n  a(href="#{code}")= code',
            from: "System"
          });
        }
      };
      ndx.setForgotTemplate = function(template) {
        var forgotTemplate;
        return forgotTemplate = template;
      };
      ndx.app.post('/get-forgot-code', function(req, res, next) {
        return ndx.passport.fetchByEmail(req.body.email, function(users) {
          if (users && users.length) {
            return ndx.invite.tokenFromUser(users[0], function(token) {
              var host;
              host = process.env.HOST || ndx.settings.HOST || (req.protocol + "://" + req.hostname);
              return ndx.forgot.fetchTemplate(req.body, function(forgotTemplate) {
                if (ndx.email) {
                  ndx.email.send({
                    to: req.body.email,
                    from: forgotTemplate.from,
                    subject: forgotTemplate.subject,
                    body: forgotTemplate.body,
                    code: host + "/forgot/" + token,
                    host: host,
                    user: users[0]
                  });
                  ndx.passport.syncCallback('resetPasswordRequest', {
                    obj: users[0],
                    code: token
                  });
                }
                return res.end(token);
              });
            });
          } else {
            return next('No user found');
          }
        });
      });
      return ndx.app.post('/forgot-update/:code', function(req, res, next) {
        var user;
        user = JSON.parse(ndx.parseToken(req.params.code, true));
        return ndx.invite.userFromToken(req.params.code, function(err, user) {
          var where;
          if (req.body.password) {
            where = {};
            where[ndx.settings.AUTO_ID] = user[ndx.settings.AUTO_ID];
            ndx.database.update(ndx.settings.USER_TABLE, {
              local: {
                email: user.email,
                password: ndx.generateHash(req.body.password)
              }
            }, where);
            if (ndx.shortToken) {
              ndx.shortToken.remove(req.params.code);
            }
            ndx.passport.syncCallback('resetPassword', {
              obj: user,
              code: req.params.code
            });
            return res.end('OK');
          } else {
            return next('No password');
          }
        });
      });
    }
  };

}).call(this);

//# sourceMappingURL=forgot.js.map
