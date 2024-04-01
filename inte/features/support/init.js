const apickli = require('apickli');
const fs = require('fs');
const {
  Before, BeforeAll,
} = require('@cucumber/cucumber');

BeforeAll((cb) => {
  apickli.Apickli.prototype.sendEncrypted = async function func(isRenewal, method, resource, callback) {
    const self = this;

    const options = {
      ...this.httpRequestOptions,
      method,
      headers: this.headers,
      body: this.requestBody,
    };

    const timeMS = Date.now();
    try {
      let response;
      if (isRenewal) {
        response = await this.alsClient.callAndRenew(resource, options);
      } else {
        response = await this.alsClient.call(resource, options);
      }

      console.log('fetch duration', Date.now() - timeMS);

      self.httpResponse.headers = {};
      response.headers.forEach((value, key) => {
        self.httpResponse.headers[key] = value;
      });
      self.httpResponse.body = await response.text();
      self.httpResponse.statusCode = response.status;
      callback(null, self.httpResponse);
    } catch (err) {
      callback(err);
    }
  };
  cb();
});

Before(async function () {
  const ALSClient = (await import('@protocol/client')).default;
  const host = 'localhost:4000';
  const protocol = 'http';

  const pem = fs.readFileSync(`${__dirname}/../data/rsaPK.pem`, 'utf-8');
  const publicHeader = '-----BEGIN PUBLIC KEY-----';
  const publicFooter = '-----END PUBLIC KEY-----';
  const trimmedPK = pem.replace(/\n/g, '');
  const pemPK = trimmedPK.substring(publicHeader.length, trimmedPK.length - publicFooter.length);
  this.PK_SIG_ANON_CLAIM = pemPK;

  const storage = {
    get: (n) => this.apickli.scenarioVariables[n],
    set: (n, v) => {
      this.apickli.storeValueInScenarioScope(n, v);
    },
    has: (n) => !!this.apickli.scenarioVariables[n],
    clear: (n) => {
      this.apickli.storeValueInScenarioScope(n, undefined);
    },
  };

  this.apickli = new apickli.Apickli(protocol, host, 'data');
  this.apickli.alsClient = new ALSClient(`${protocol}://${host}`, storage);
  this.apickli.addRequestHeader('Cache-Control', 'no-cache');
  this.apickli.addRequestHeader('Content-Type', 'application/json');
  this.apickli.storeValueInScenarioScope('PK_SIG_ANON_CLAIM', this.PK_SIG_ANON_CLAIM);

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
