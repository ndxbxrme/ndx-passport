'use strict'

module.exports = (ndx) ->
  if ndx.settings.HAS_FORGOT or process.env.HAS_FORGOT
    ndx.forgot =
      fetchTemplate: (data, cb) ->
        cb
          subject: "forgot password"
          body: 'h1 forgot password\np\n  a(href="#{code}")= code'
          from: "System"
    ndx.setForgotTemplate = (template) ->
      forgotTemplate = template
    ndx.app.post '/get-forgot-code', (req, res, next) ->
      ndx.passport.fetchByEmail req.body.email, (users) ->
        if users and users.length
          ndx.invite.tokenFromUser users[0], (token) ->
            host = process.env.HOST or ndx.settings.HOST or "#{req.protocol}://#{req.hostname}" 
            ndx.forgot.fetchTemplate req.body, (forgotTemplate) ->
              if ndx.email
                ndx.email.send
                  to: req.body.email
                  from: forgotTemplate.from
                  subject: forgotTemplate.subject
                  body: forgotTemplate.body
                  code: "#{host}/forgot/#{token}"
                  user: users[0]
                ndx.passport.syncCallback 'resetPasswordRequest',
                  obj: users[0]
                  code: token
              res.end token
        else
          return next 'No user found'
    ndx.app.post '/forgot-update/:code', (req, res, next) ->
      user = JSON.parse ndx.parseToken(req.params.code, true)
      ndx.invite.userFromToken req.params.code, (err, user) ->
        if req.body.password
          where = {}
          where[ndx.settings.AUTO_ID] = user[ndx.settings.AUTO_ID]
          ndx.database.update ndx.settings.USER_TABLE,
            local:
              email: user.email
              password: ndx.generateHash req.body.password
          , where
          if ndx.shortToken
            ndx.shortToken.remove req.params.code
          ndx.passport.syncCallback 'resetPassword',
            obj: user
            code: req.params.code
          res.end 'OK'
        else
          next 'No password'