const apickli = require('apickli');
const request = require('request');
const fs = require('fs');
const {
  Before, BeforeAll,
} = require('@cucumber/cucumber');
const Helper = require('./helper');

BeforeAll((cb) => {
  apickli.Apickli.prototype.sendEncrypted = function (method, resource, callback) {
    const self = this;

    const options = this.httpRequestOptions || {};
    const encBody = {};
    encBody.url = resource;
    encBody.method = method;
    encBody.headers = this.headers;
    encBody.body = this.requestBody;

    const tss = this.scenarioVariables.SHARED_SECRET;

    const body = Helper.encryptRequest(Buffer.from(JSON.stringify(encBody)), Buffer.from(tss, 'base64url'));

    console.log('this.scenarioVariables.EC_SIG_CLIENT_SK', this.scenarioVariables.EC_SIG_CLIENT_SK);
    const key = Buffer.from(this.scenarioVariables.EC_SIG_CLIENT_SK, 'base64url');
    const signature = Helper.signWithEcdsa(Buffer.from(body), this.scenarioVariables.EC_SIG_CLIENT_SK);

    options.url = `${this.domain}/api`;
    options.method = 'POST';
    options.headers.Authorization = this.headers.Authorization;
    options.headers['X-Signature-Request'] = signature.toString('base64url');
    options.headers['Content-Type'] = 'text/plain';
    options.headers['Content-Length'] = Buffer.from(body, 'utf8').length;
    options.body = body;

    request(options, (error, response) => {
      if (error) {
        return callback(error);
      }
      console.log('raw response.body', response.body);
      console.log('raw response.statusCode', response.statusCode);

      self.httpResponse = response;
      if (response.statusCode < 300) {
        self.httpResponse.body = Helper.decryptResponse(response.body, Buffer.from(tss, 'base64url'));
      }
      return callback(null, response);
    });
  };

  cb();
});

Before(function () {
  const host = 'localhost:4000';
  const protocol = 'http';

  const pem = fs.readFileSync(`${__dirname}/../data/rsaPK.pem`);
  this.PK_SIG_ANON_CLAIM = pem;

  this.apickli = new apickli.Apickli(protocol, host, 'data');
  this.apickli.addRequestHeader('Cache-Control', 'no-cache');
  this.apickli.addRequestHeader('Content-Type', 'application/json');

  this.get = (url) => new Promise((resolve, reject) => {
    this.apickli.get(url, (error) => {
      if (error) {
        reject(error);
      }

      resolve();
    });
  });
  this.post = (url) => new Promise((resolve, reject) => {
    this.apickli.post(url, (error) => {
      if (error) {
        reject(error);
      }
      resolve();
    });
  });
  this.put = (url) => new Promise((resolve, reject) => {
    this.apickli.put(url, (error) => {
      if (error) {
        reject(error);
      }
      resolve();
    });
  });
  this.delete = (url) => new Promise((resolve, reject) => {
    this.apickli.delete(url, (error) => {
      if (error) {
        reject(error);
      }
      resolve();
    });
  });
});
