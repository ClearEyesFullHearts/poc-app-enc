const apickli = require('apickli');
const request = require('request');
const fs = require('fs');
const {
  Before, BeforeAll,
} = require('@cucumber/cucumber');
const Helper = require('./helper');

BeforeAll((cb) => {
  Helper.init().then(() => {
    apickli.Apickli.prototype.sendEncrypted = async function sendEncrypted(method, resource, callback) {
      const self = this;

      const options = this.httpRequestOptions || {};
      const encBody = {};
      encBody.url = resource;
      encBody.method = method;
      encBody.headers = this.headers;
      encBody.body = this.requestBody;

      const tss = this.scenarioVariables.SHARED_SECRET;

      const body = await Helper.encryptRequest(JSON.stringify(encBody), tss, {});

      const pem = this.scenarioVariables.EC_SIG_CLIENT_SK;
      const signature = await Helper.cryptoHelper.signWithEcdsa(body, pem);

      options.url = `${this.domain}/protected`;
      options.method = 'POST';
      options.headers.Authorization = this.headers.Authorization;
      options.headers['X-Signature-Request'] = signature.toString('base64url');
      options.headers['Content-Type'] = 'text/plain';
      options.headers['Content-Length'] = Buffer.from(body, 'utf8').length;
      options.body = body;

      request(options, async (error, response) => {
        if (error) {
          return callback(error);
        }

        self.httpResponse = response;
        if (response.statusCode < 300) {
          const proof = response.headers['x-signature-response'];
          const sigKey = this.scenarioVariables.EC_SIG_SERVER_PK;

          const isVerifed = await Helper.cryptoHelper.verifyWithECDSA(response.body, proof, sigKey);

          if (!isVerifed) throw new Error('Signature is wrong');
          self.httpResponse.body = await Helper.decryptResponse(response.body, tss);
        }
        return callback(null, response);
      });
    };

    cb();
  });
});

Before(function () {
  const host = 'localhost:4000';
  const protocol = 'http';

  const pem = fs.readFileSync(`${__dirname}/../data/rsaPK.pem`, 'utf-8');
  const publicHeader = '-----BEGIN PUBLIC KEY-----';
  const publicFooter = '-----END PUBLIC KEY-----';
  const trimmedPK = pem.replace(/\n/g, '');
  const pemPK = trimmedPK.substring(publicHeader.length, trimmedPK.length - publicFooter.length);
  this.PK_SIG_ANON_CLAIM = pemPK;

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
