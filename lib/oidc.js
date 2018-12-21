'use strict';

const get = require('./http-then').get;

class OpenIdConnect {

  constructor(/* User.AuthProvider */ auth_provider) {
    this.auth_provider = auth_provider;
  }

  refresh_token(options, client, cancellable = false, cancellations) {
    // only fetch the token url once
    const promise = client.token_url ? Promise.resolve() : getBody(client.provider_configuration_url(), cancellable, cancellations);
    return promise
      .then(response => client.token_url = response ? JSON.parse(response.body.toString('utf8')).token_endpoint : client.token_url)
      .then(() => getBody(client.refresh_token(), cancellable, cancellations))
      .then(response => {
        const body = JSON.parse(response.body.toString('utf8'));
        client.jwt = body.id_token;
        options.headers['Authorization'] = `Bearer ${client.jwt}`;
      });
  }

  get token_url() {
    return this._token_url;
  }

  set token_url(url) {
    this._token_url = url;
  }

  set token_expiry_time(exp) {
    this._token_expiry_time = exp;
  }

  get token_expiry_time() {
    if (this._token_expiry_time)
      return this._token_expiry_time;
    this.jwt = this.master_api.auth_provider.token;
    return this._token_expiry_time;
  }

  set jwt(jwt) {
    this.master_api.auth_provider.token = jwt;
    this.master_api.headers['Authorization'] = `Bearer ${jwt}`;
    const part = jwt.split('.')[1];
    const payload = Buffer.from(part, 'base64');
    this.token_expiry_time = JSON.parse(payload).exp;
  }

  get jwt() {
    if (!this.master_api.auth_provider) {
      return undefined;
    }
    return this.master_api.auth_provider.token;
  }

  token_expired() {
    if (!this.master_api.auth_provider) {
      return false;
    }
    return (this.token_expiry_time - Date.now() / 1000) < 10;
  }

  provider_configuration_url() {
    // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
    return new HttpOptions(this.master_api.auth_provider.url + '/.well-known/openid-configuration');
  }

  refresh_token() {
    const headers = {
      'content-type' : 'application/json',
    };
    const postData = {
      grant_type    : 'refresh_token',
      client_id     : `${this.master_api.auth_provider.client_id}`,
      client_secret : `${this.master_api.auth_provider.client_secret}`,
      refresh_token : `${this.master_api.auth_provider.refresh_token}`,
    };
    return new HttpOptions(this.token_url, headers, 'POST', postData);
  }
}

module.exports = OpenIdConnect;
