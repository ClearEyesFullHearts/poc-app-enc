const { Given, When, Then } = require('@cucumber/cucumber');

Given(/^I generate a session key pair$/, async function () {
  const {
    EC_ENC_CLIENT_PK,
    EC_ENC_CLIENT_SK,
    EC_SIG_CLIENT_PK,
    EC_SIG_CLIENT_SK,
  } = await this.apickli.alsClient.generateKeys();

  this.apickli.storeValueInScenarioScope('PK_ENC', EC_ENC_CLIENT_PK);
  this.apickli.storeValueInScenarioScope('PK_SIG', EC_SIG_CLIENT_PK);
  this.apickli.storeValueInScenarioScope('SK_ENC', EC_ENC_CLIENT_SK);
  this.apickli.storeValueInScenarioScope('SK_SIG', EC_SIG_CLIENT_SK);
});

When(/^I API POST to (.*)$/, async function (resource) {
  const target = this.apickli.replaceVariables(resource);
  const isRenewal = target === '/login';

  await new Promise((resolve, reject) => {
    this.apickli.sendEncrypted(isRenewal, 'POST', target, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
});

When(/^I API GET (.*)$/, async function (resource) {
  const target = this.apickli.replaceVariables(resource);
  this.apickli.requestBody = undefined;

  await new Promise((resolve, reject) => {
    this.apickli.sendEncrypted(false, 'GET', target, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
});

Then(/^I set session from response headers$/, async function () {
  const encSK = this.apickli.scenarioVariables.SK_ENC;
  const sigSK = this.apickli.scenarioVariables.SK_SIG;

  const token = this.apickli.getResponseObject().headers['x-auth-token'];
  const [salt, publicKey] = this.apickli.getResponseObject().headers['x-servenc-pk'].split('.');
  const signatureKey = this.apickli.getResponseObject().headers['x-servsig-pk'];

  await this.apickli.alsClient.renewAuth(
    { encSK, sigSK },
    {
      token, publicKey, salt, signatureKey,
    },
  );
});
