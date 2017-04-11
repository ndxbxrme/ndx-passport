(function() {
  'use strict';
  module.exports = function(ndx) {
    if (ndx.settings.HAS_FORGOT || process.env.HAS_FORGOT) {
      ndx.forgot = {
        fetchTemplate: function() {
          return {
            subject: "forgot password",
            body: 'h1 forgot password\np\n  a(href="#{code}")= code',
            from: "System"
          };
        }
      };
      ndx.setForgotTemplate = function(template) {
        var forgotTemplate;
        return forgotTemplate = template;
      };
      ndx.app.post('/get-forgot-code', function(req, res, next) {
        return ndx.database.select(ndx.settings.USER_TABLE, {
          where: {
            local: {
              email: req.body.email
            }
          }
        }, function(users) {
          var forgotTemplate, token;
          if (users && users.length) {
            token = encodeURIComponent(ndx.generateToken(JSON.stringify(req.body), req.ip, 4 * 24, true));
            token = req.protocol + "://" + req.hostname + "/invite/" + token;
            forgotTemplate = ndx.forgot.fetchTemplate(req.body);
            if (ndx.email) {
              ndx.email.send({
                to: req.body.email,
                from: forgotTemplate.from,
                subject: forgotTemplate.subject,
                body: forgotTemplate.body,
                code: token,
                user: users[0]
              });
            }
            return res.end(token);
          } else {
            return next('No user found');
          }
        });
      });
      return ndx.app.post('/forgot/:code', function(req, res, next) {
        var user, where;
        user = ndx.parseToken(req.params.code, true);
        if (req.body.password) {
          where = {};
          where[ndx.settings.AUTO_ID] = user;
          ndx.database.update(ndx.settings.USER_TABLE, {
            local: {
              password: ndx.generateHash(req.body.password)
            }
          }, where);
          return res.end('OK');
        } else {
          return next('No password');
        }
      });
    }
  };

}).call(this);

//# sourceMappingURL=forgot.js.map
