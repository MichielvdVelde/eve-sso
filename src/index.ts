'use strict'

import { stringify } from 'querystring'

import bent from 'bent'
import formUrlEncoded from 'form-urlencoded'
import jwt from 'jsonwebtoken'
import jwksClient from 'jwks-rsa'

const { name, version, homepage } = require('../package')

export interface AccessToken {
  scp: string | string[],
  jti: string,
  kid: string,
  sub: string,
  azp: string,
  name: string,
  owner: string,
  exp: number,
  iss: string
}

export interface Response {
  access_token: string,
  decoded_access_token: AccessToken,
  expires_in: number,
  token_type: string,
  refresh_token: string,
  headers: {
    [key: string]: any
  }
}

export interface SingleSignOnOptions {
  endpoint?: string
  userAgent?: string
}

export default class SingleSignOn {
  public readonly clientId: string
  public readonly callbackUri: string
  public readonly endpoint: string
  public readonly host: string
  public readonly userAgent: string
  public readonly jwksClient: jwksClient.JwksClient

  #request: bent.RequestFunction<bent.NodeResponse>

  public constructor (
    clientId: string,
    secretKey: string,
    callbackUri: string,
    opts: SingleSignOnOptions = {}
  ) {
    this.clientId = clientId
    this.callbackUri = callbackUri

    this.endpoint = opts.endpoint || 'https://login.eveonline.com'
    this.userAgent = opts.userAgent || `${name}@${version} - nodejs@${process.version} - ${homepage}`

    const authorization = Buffer.from(`${this.clientId}:${secretKey}`).toString('base64')
    this.host = new URL(this.endpoint).hostname

    this.#request = bent(this.endpoint, 'POST', {
      Host: this.host,
      Authorization: `Basic ${authorization}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': this.userAgent
    }) as bent.RequestFunction<bent.NodeResponse>

    this.jwksClient = jwksClient({
      jwksUri: `${this.endpoint}/oauth/jwks`,
      requestHeaders: {
        'User-Agent': this.userAgent
      }
    })
  }

  /**
   * Get a redirect url.
   * @param  state  State string
   * @param  scopes Scopes to request
   * @return        Redirect url
   */
  public getRedirectUrl (state: string, scopes?: string | string[]) {
    let scope: string = ''

    if (scopes) {
      scope = Array.isArray(scopes) ? scopes.join(' ') : scopes
    }

    const query: any = {
      response_type: 'code',
      redirect_uri: this.callbackUri,
      client_id: this.clientId,
      scope,
      state
    }

    return `${this.endpoint}/v2/oauth/authorize?${stringify(query)}`
  }

  /**
   * Get an access token from an authorization code or refresh token.
   * @param  code           The authorization code or refresh token
   * @param  isRefreshToken Whether or not a refresh token is used
   * @param  scopes         A subset of the specified scopes
   * @return                An object containing, among other things,
   * the access token and refresh token
   */
  public async getAccessToken (
    code: string,
    isRefreshToken?: boolean,
    scopes?: string | string[]
  ): Promise<Response> {
    let payload: any

    if (!isRefreshToken) {
      payload = {
        grant_type: 'authorization_code',
        code
      }
    } else {
      payload = {
        grant_type: 'refresh_token',
        refresh_token: code
      }

      if (scopes) {
        payload.scope = Array.isArray(scopes) ? scopes.join(' ') : scopes
      }
    }

    const reply = await this.#request(
      '/v2/oauth/token',
      formUrlEncoded(payload)
    )

    const body: Response = await (<any>reply).json()

    body.headers = reply.headers

    body.decoded_access_token = await new Promise<AccessToken>((resolve, reject) => {
      jwt.verify(body.access_token, this.getKey.bind(this), {
        issuer: [ this.endpoint, this.host ]
      }, (err, decoded) => {
        if (err) return reject(err)
        resolve(decoded as AccessToken)
      })
    })

    return body
  }

  private getKey (header: any, callback: Function) {
    this.jwksClient.getSigningKey(header.kid, (err, key) => {
      if (err) return callback(err)
      callback(null, key.getPublicKey())
    })
  }
}
