const { Given, When } = require('@cucumber/cucumber');
const Helper = require('../support/helper');

Given(/^I get anon claim$/, async function () {
  const {
    ssk,
    spk,
  } = Helper.generateECDHKeys();

  this.apickli.setRequestBody(spk.toString('base64url'));

  this.apickli.removeRequestHeader('Content-Type');
  this.apickli.addRequestHeader('Content-Type', 'text/plain');
  await this.post('/claim');
  this.apickli.removeRequestHeader('Content-Type');
  this.apickli.addRequestHeader('Content-Type', 'application/json');

  this.apickli.setAccessTokenFromResponseBodyPath('$.token');
  this.apickli.setBearerToken();

  const {
    publicKey,
  } = JSON.parse(this.apickli.httpResponse.body);

  const tss = Helper.getSharedSecret(ssk, Buffer.from(publicKey, 'base64url'));
  this.apickli.storeValueInScenarioScope('SHARED_SECRET', tss.toString('base64url'));
});

Given(/^I generate a session key pair$/, async function () {
  const {
    ssk,
    spk,
  } = Helper.generateECDHKeys();

  this.apickli.storeValueInScenarioScope('PK', spk.toString('base64url'));
  this.apickli.storeValueInScenarioScope('SK', ssk.toString('base64url'));
});

When(/^I API POST to (.*)$/, async function (resource) {
  const target = this.apickli.replaceVariables(resource);

  await new Promise((resolve, reject) => {
    this.apickli.sendEncrypted('POST', target, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
});
