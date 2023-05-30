# Eve Single Sign On

Version 2.0.1
- Downgraded node-fetch to v2 for better Typescript compatibilily (CJS not ESM)
- Added "audience" to the JWT verification
- Added extra exception handling to JWT verification (authorisation calls at downtime used to crash)

[Eve Online](https://eveonline.com) Single Sign On (SSO) module for node.js.
Once the user/character is authenticated, you can use the access token to make
authenticated requests to [ESI](https://docs.esi.evetech.net/docs/esi_introduction.html)
(not included in this module).

For a more complete module which includes account, character, and token management
as well as the ability to make unauthenticated and authenticated requests to ESI,
see my module [eve-esi-client](https://github.com/MichielvdVelde/eve-esi).

> See the [Eve Online developer documentation](https://docs.esi.evetech.net/docs/sso/)
> for more information

## Install

```
npm i eve-sso [--save]
```

## Example

Before using the module you must create an application in the
[Eve Online developers section](https://developers.eveonline.com/). This will
give you the required client ID and secret.

A small example using koa.

```ts
import SingleSignOn from './index'
import Koa from 'koa'
import Router from 'koa-router'

// Get the client ID and secret from the Eve developers section
const CLIENT_ID = 'your client id'
const SECRET = 'your secret'
// The callback URI as defined in the application in the developers section
const CALLBACK_URI = 'http://localhost:3001/sso'

const sso = new SingleSignOn(CLIENT_ID, SECRET, CALLBACK_URI, {
  endpoint: 'https://login.eveonline.com', // optional, defaults to this
  userAgent: 'my-user-agent' // optional
})

const app = new Koa()
const router = new Router()

// Show a login redirect link
router.get('/login', async ctx => {
  // The first argument is a required state, which you can verify in the callback
  // The second argument is an optional space-delimited string or string array of scopes to request
  ctx.body = `<a href="${sso.getRedirectUrl('my-state')}">Login to Eve Online</a>`
})

// Handle the SSO callback (this route is the CALLBACK_URI above)
router.get('/sso', async ctx => {
  // Get the one-time access code
  const code: string = ctx.query.code
  // NOTE: usually you'd want to validate the state (ctx.query.state) as well

  // Swap the one-time code for an access token
  const info = await sso.getAccessToken(code)

  // Usually you'd want to store the access token
  // as well as the refresh token
  console.log('info', info)
  
  // Do whatever, for example, redirect to user page
  ctx.body = 'You are now authenticated!'
})

app.use(router.middleware())
app.listen(3001, () => {
  console.log('Server listening on port 3001')
})

```

## License

Copyright 2020-2021 Michiel van der Velde.

This software is licensed under [the MIT License](LICENSE).
