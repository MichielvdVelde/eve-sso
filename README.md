# Eve Single Sign On

[Eve Online](https://eveonline.com) Single Sign On (SSO) module for node.js.
Once the user/character is authenticated, you can use the access token to make
authenticated requests to [ESI](https://docs.esi.evetech.net/docs/esi_introduction.html)
(not included in this module).

Supports defining scopes as well. For now, please refer to the source code
or the example for more information on how to use this module (documentation
is forthcoming).

The received access token is automatically verified as well.

Before using the module you must create an application in the
[Eve Online developers section](https://developers.eveonline.com/). This will
give you the required client ID and secret.

[See the developer documentation for more information](https://docs.esi.evetech.net/docs/sso/).

## Example

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
  userAgent: 'my-user-agent', // optional
  scopes: [ 'scope1', 'scope2' ] // scopes to request
})

const app = new Koa()
const router = new Router()

// Show a login redirect link
router.get('/login', async ctx => {
  // The first argument is an optional state, which you can verify in the callback
  // The second argument is an optional space-delimited string or string array of scopes to request
  // (which will overwrite the scopes given in the constructor options, if any)
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

Copyright 2020 Michiel van der Velde.

This software is licensed under [the MIT License](LICENSE).
