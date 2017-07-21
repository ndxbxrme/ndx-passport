'use strict'

module.exports = (ndx) ->
  if ndx.settings.HAS_INVITE or process.env.HAS_INVITE
    if typeof btoa is 'undefined'
      global.btoa = (str) ->
        new Buffer(str).toString 'base64'
    if typeof atob is 'undefined'
      global.atob = (b64Encoded) ->
        new Buffer(b64Encoded, 'base64').toString()
    userFromToken = (token, cb) ->
      parseToken = (token, cb) ->
        try
          cb null, JSON.parse ndx.parseToken(atob(decodeURIComponent(token)), true)
        catch e
          return cb e
      if ndx.shortToken
        ndx.shortToken.fetch token, (err, _token) ->
          if err
            cb err
          else
            parseToken _token, cb
      else
        parseToken token, cb
    tokenFromUser = (user, cb) ->
      token = encodeURIComponent(btoa(ndx.generateToken(JSON.stringify(user), null, 4 * 24, true)))
      if ndx.shortToken
        ndx.shortToken.generate token, (shortToken) ->
          cb shortToken
      else
        cb token
    ndx.invite = 
      fetchTemplate: (data, cb) ->
        cb
          subject: "You have been invited"
          body: 'h1 invite\np\n  a(href="#{code}")= code'
          from: "System"
      users: ['admin', 'superadmin']
    ndx.app.post '/invite/accept', (req, res, next) ->
      userFromToken req.body.code, (err, user) ->
        if err
          return next err
        else
          ndx.database.select ndx.settings.USER_TABLE,
            where:
              local:
                email: user.local.email
          , (users) ->
            if users and users.length
              return next 'User already exists'
            delete req.body.user.roles
            delete req.body.user.type
            ndx.extend user, req.body.user
            user.local.password = ndx.generateHash user.local.password
            ndx.database.insert ndx.settings.USER_TABLE, user
            res.end 'OK'
    ndx.app.get '/invite/:code', (req, res, next) ->
      userFromToken req.params.code, (err, user) ->
        if err
          return next err
        res.redirect "/invited?#{encodeURIComponent(req.params.code)}++#{btoa(JSON.stringify(user))}"
    ndx.app.post '/api/get-invite-code', ndx.authenticate(ndx.invite.users), (req, res, next) ->
      ndx.database.select ndx.settings.USER_TABLE,
        where:
          local:
            email: req.body.local.email
      , (users) ->
        if users and users.length
          return next 'User already exists'
        tokenFromUser req.body, (token) ->
          host = process.env.HOST or ndx.settings.HOST or "#{req.protocol}://#{req.hostname}"
          token = "#{host}/invite/#{token}"
          ndx.invite.fetchTemplate req.body, (inviteTemplate) ->
            if ndx.email
              ndx.email.send
                to: req.body.local.email
                from: inviteTemplate.from
                subject: inviteTemplate.subject
                body: inviteTemplate.body
                code: token
            res.end token
