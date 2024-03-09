const { Given, When } = require('@cucumber/cucumber');
const Helper = require('../support/helper');

Given(/^I get anon claim$/, async function () {
  const {
    ssk: EC_ENC_CLIENT_SK,
    spk: EC_ENC_CLIENT_PK,
  } = Helper.generateECDHKeys();
  const {
    ssk: EC_SIG_CLIENT_SK,
    spk: EC_SIG_CLIENT_PK,
  } = Helper.generateECDHKeys();

  this.apickli.setRequestBody(JSON.stringify({
    publicKey: EC_ENC_CLIENT_PK.toString('base64url'),
    signingKey: EC_SIG_CLIENT_PK.toString('base64url'),
  }));

  await this.post('/claim');

  const {
    token,
    publicKey,
    salt,
    signature,
  } = JSON.parse(this.apickli.httpResponse.body);

  this.apickli.setAccessTokenFromResponseBodyPath('$.token');
  this.apickli.setBearerToken();

  const rsaPK = this.PK_SIG_ANON_CLAIM;

  const digest = Buffer.from(JSON.stringify({
    token,
    publicKey,
    salt,
  }));
  const isVerified = Helper.verifyRSASignature(digest, Buffer.from(signature, 'base64url'), rsaPK);

  if (!isVerified) {
    throw new Error('RSA signature is wrong');
  }

  const tss = Helper.getSharedSecret(EC_ENC_CLIENT_SK, Buffer.from(publicKey, 'base64url'), Buffer.from(salt, 'base64url'));
  this.apickli.storeValueInScenarioScope('SHARED_SECRET', tss.toString('base64url'));
  this.apickli.storeValueInScenarioScope('EC_SIG_CLIENT_SK', EC_SIG_CLIENT_SK.toString('base64url'));
});

Given(/^I generate a session key pair$/, async function () {
  const {
    ssk: EC_ENC_CLIENT_SK,
    spk: EC_ENC_CLIENT_PK,
  } = Helper.generateECDHKeys();
  const {
    ssk: EC_SIG_CLIENT_SK,
    spk: EC_SIG_CLIENT_PK,
  } = Helper.generateECDHKeys();

  this.apickli.storeValueInScenarioScope('EC_ENC_CLIENT_PK', EC_ENC_CLIENT_PK.toString('base64url'));
  this.apickli.storeValueInScenarioScope('EC_ENC_CLIENT_SK', EC_ENC_CLIENT_SK.toString('base64url'));
  this.apickli.storeValueInScenarioScope('EC_SIG_CLIENT_PK', EC_SIG_CLIENT_PK.toString('base64url'));
  this.apickli.storeValueInScenarioScope('EC_SIG_CLIENT_SK', EC_SIG_CLIENT_SK.toString('base64url'));
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
