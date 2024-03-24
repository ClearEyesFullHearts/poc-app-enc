const { Given, When } = require('@cucumber/cucumber');
const Helper = require('../support/helper');

Given(/^I get anon claim$/, async function () {
  const {
    privateKey: EC_ENC_CLIENT_SK,
    publicKey: EC_ENC_CLIENT_PK,
  } = await Helper.cryptoHelper.generateECDHKeys();
  const {
    privateKey: EC_SIG_CLIENT_SK,
    publicKey: EC_SIG_CLIENT_PK,
  } = await Helper.cryptoHelper.generateECDSAKeys();

  this.apickli.setRequestBody(JSON.stringify({
    publicKey: EC_ENC_CLIENT_PK,
    signingKey: EC_SIG_CLIENT_PK,
  }));

  await this.post('/claim');

  const {
    token,
    publicKey,
    signatureKey,
    salt,
    signature,
  } = JSON.parse(this.apickli.httpResponse.body);

  this.apickli.setAccessTokenFromResponseBodyPath('$.token');
  this.apickli.setBearerToken();

  const rsaPK = this.PK_SIG_ANON_CLAIM;

  const digest = JSON.stringify({
    token,
    publicKey,
    signatureKey,
    salt,
  });
  const isVerified = await Helper.cryptoHelper.verifyRSASignature(digest, signature, rsaPK);

  if (!isVerified) {
    throw new Error('RSA signature is wrong');
  }

  const tss = await Helper.cryptoHelper.getSharedSecret(publicKey, EC_ENC_CLIENT_SK, salt);
  this.apickli.storeValueInScenarioScope('SHARED_SECRET', tss);
  this.apickli.storeValueInScenarioScope('EC_SIG_CLIENT_SK', EC_SIG_CLIENT_SK);
  this.apickli.storeValueInScenarioScope('EC_SIG_SERVER_PK', signatureKey);
});

Given(/^I generate a session key pair$/, async function () {
  const {
    privateKey: EC_ENC_CLIENT_SK,
    publicKey: EC_ENC_CLIENT_PK,
  } = await Helper.cryptoHelper.generateECDHKeys();
  const {
    privateKey: EC_SIG_CLIENT_SK,
    publicKey: EC_SIG_CLIENT_PK,
  } = await Helper.cryptoHelper.generateECDSAKeys();

  console.log('pk length\n', EC_SIG_CLIENT_PK.length, EC_SIG_CLIENT_PK);

  this.apickli.storeValueInScenarioScope('PK_ENC', EC_ENC_CLIENT_PK);
  this.apickli.storeValueInScenarioScope('PK_SIG', EC_SIG_CLIENT_PK);
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
