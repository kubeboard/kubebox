'use strict';

const crypto = require('crypto'),
      get    = require('./http-then').get,
      get    = require('./oidc'),
      URI    = require('urijs');

class Request {

  constructor(options) {
    this.options = options;
  }

  get({ generator, readable, async = true, cancellable = false } = {}) {

    if (this.oidc) {
      if (oidc.token_expired()) {
        refresh = oidc.refresh_token(options, client, cancellable, cancellations);
      }

    } else {
      return get(this.options, { generator, readable, async, cancellable });
    }
  }
}

class WatchableRequest extends Request {

  constructor(options) {
    super(options);
  }

  watch(resourceVersion, { fieldSelector } = {}) {
    const uri = URI(this.options.path)
      .addQuery('watch', true)
      .addQuery('resourceVersion', resourceVersion);
    if (fieldSelector) uri.addQuery('fieldSelector', fieldSelector);
    return new Request(merge({
      path    : uri.toString(),
      headers : {
        // https://tools.ietf.org/html/rfc6455
        Origin                 : this.master_api.url,
        Connection             : 'Upgrade',
        Upgrade                : 'websocket',
        'Sec-WebSocket-Key'    : crypto.createHash('SHA1').digest('base64'),
        'Sec-WebSocket-Version': 13,
      }
    }, this.options));
  }
}

class PodRequest extends Request {

  constructor(options) {
    super(options);
  }

  exec({ command = [], container } = {}) {
    const uri = URI(this.options.path)
      .segment('exec')
      .addQuery('stdout', 1)
      .addQuery('stdin', 1)
      .addQuery('stderr', 1)
      .addQuery('tty', 1);
    if (container) uri.addQuery('container', container);
    command.forEach(c => uri.addQuery('command', c));
    return new Request(merge({
      path    : uri.toString(),
      headers : {
        // https://tools.ietf.org/html/rfc6455
        Connection               : 'Upgrade',
        Upgrade                  : 'WebSocket',
        'Sec-WebSocket-Protocol' : 'channel.k8s.io',
        'Sec-WebSocket-Key'      : crypto.createHash('SHA1').digest('base64'),
        'Sec-WebSocket-Version'  : 13,
      }
    }, this.options));
  }

  log({ sinceTime, container } = {}) {
    const uri = URI(this.options.path)
      .segment('log')
      .addQuery('follow', true)
      .addQuery('tailLines', 10000)
      .addQuery('timestamps', true);
    if (container) uri.addQuery('container', container);
    if (sinceTime) uri.addQuery('sinceTime', sinceTime);
    // TODO: limit the amount of data with the limitBytes parameter
    return new Request(merge({
      path    : uri.toString(),
      headers : {
        // https://tools.ietf.org/html/rfc6455
        Connection               : 'Upgrade',
        Upgrade                  : 'WebSocket',
        'Sec-WebSocket-Protocol' : 'binary.k8s.io',
        'Sec-WebSocket-Key'      : crypto.createHash('SHA1').digest('base64'),
        'Sec-WebSocket-Version'  : 13,
      }
    }, this.options));
  }
}

class Client {

  constructor(master_api) {
    // should ideally be a defensive copy
    this.master_api = master_api;
    this.paths = [];
  }

  get master_api() {
    return this._master_api;
  }

  set master_api(master_api) {
    this.paths = [];
    this._master_api = master_api;
    if (master_api.auth_provider) {
      this.oidc = new OpenIdConnect(master_api.auth_provider);
    } else {
      delete this.oidc;
    }
  }

  get headers() {
    return this.master_api.headers;
  }

  get url() {
    return this.master_api.url;
  }

/*   set url(url) {
    this.master_api.url = url;
  } */

  get openshift() {
    return this.paths.some(path => path === '/oapi' || path === '/oapi/v1');
  }

  api() {
    return new Request(merge({
      path   : '/api',
      method : 'GET',
    },
    this.master_api));
  }

  paths({ authorization } = { authorization: true }) {
    const request = merge({
      path   : '/',
      method : 'GET',
    },
    this.master_api);
    if (!authorization && !this.jwt) {
      delete request.headers['Authorization'];
    }
    return new Request(request);
  }

  // https://docs.openshift.org/latest/architecture/additional_concepts/authentication.html
  // https://github.com/openshift/openshift-docs/issues/707
  oauth_authorize({ username, password }) {
    delete this.master_api.headers['Authorization'];
    return new Request(merge({
      path    : '/oauth/authorize?client_id=openshift-challenging-client&response_type=token',
      method  : 'GET',
      auth    : `${username}:${password}`,
      headers : {
        'X-Csrf-Token' : '1',
      },
    }, this.master_api));
  }

  oauth_authorize_web({ username, password }) {
    delete this.master_api.headers['Authorization'];
    return new Request(merge({
      path    : `/oauth/authorize?client_id=openshift-browser-client&redirect_uri=${new URI(this.master_api.url).segment('/oauth/token/display')}&response_type=code`,
      method  : 'GET',
      auth    : `${username}:${password}`,
      headers : {
        'X-Csrf-Token' : '1',
      },
    }, this.master_api));
  }

  // token can be passed to test authentication
  user(token) {
    const request = merge({
      path    : '/oapi/v1/users/~',
      method  : 'GET',
      headers : {},
    }, this.master_api);
    if (token) {
      request.headers['Authorization'] = `Bearer ${token}`;
    }
    return new Request(request);
  }

  namespaces() {
    return new Request(merge({
      path   : '/api/v1/namespaces',
      method : 'GET'
    }, this.master_api));
 }

  projects() {
    return new Request(merge({
      path   : '/oapi/v1/projects',
      method : 'GET'
    }, this.master_api));
  }

  pods(namespace) {
    return new WatchableRequest(merge({
      path   : `/api/v1/namespaces/${namespace}/pods`,
      method : 'GET'
    }, this.master_api));
  }

  pod(namespace, name) {
    return new PodRequest(merge({
      path   : `/api/v1/namespaces/${namespace}/pods/${name}`,
      method : 'GET'
    }, this.master_api));
  }

  // Endpoints to resources usage metrics.
  //
  // The target is to rely on the Metrics API that is served by the Metrics server and accessed
  // from the the Master API.
  // See https://kubernetes.io/docs/tasks/debug-application-cluster/core-metrics-pipeline/
  //
  // However, the Metrics API is still limited and requires the Metrics server to be deployed
  // (default for clusters created by the kube-up.sh script).
  //
  // Design documentation can be found at the following location:
  // https://github.com/kubernetes/community/tree/master/contributors/design-proposals/instrumentation
  //
  // In the meantime, metrics are retrieved from the Kubelet /stats endpoint.

  // Gets the stats from the Summary API exposed by Kubelet on the specified node
  summary_stats(node) {
    return new Request(merge({
      path   : `/api/v1/nodes/${node}/proxy/stats/summary`,
      method : 'GET',
    }, this.master_api));
  }

  // Gets the cAdvisor data collected by Kubelet and exposed on the /stats endpoint.
  // It may be broken in previous k8s versions, see:
  // https://github.com/kubernetes/kubernetes/issues/56297
  // This cAdvisor endpoint will eventually be removed, see:
  // https://github.com/kubernetes/kubernetes/issues/68522
  container_stats(node, namespace, pod, uid, container) {
    return new Request(merge({
      path   : `/api/v1/nodes/${node}/proxy/stats/${namespace}/${pod}/${uid}/${container}`,
      method : 'GET',
    }, this.master_api));
  }
}

function merge(target, source) {
  return Object.keys(source).reduce((target, key) => {
    const prop = source[key];
    if (typeof prop === 'object' && Object.prototype.toString.call(prop) === '[object Object]') {
      // Only deep copy Object
      if (!target[key]) target[key] = {};
      merge(target[key], prop);
    } else if (typeof target[key] === 'undefined') {
      target[key] = prop;
    } else if (key === 'path' && source.path) {
      target.path = URI.joinPaths(source.path, target.path)
        .query(URI.parse(target.path).query || '')
        .resource();
    }
    return target;
  }, target);
}

module.exports = Client;
