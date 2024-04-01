import AlsClient from '@protocol/client';

const storage = {
  get: (n) => sessionStorage.getItem(n),
  set: (n, v) => {
    sessionStorage.setItem(n, v);
  },
  has: (n) => !!sessionStorage.getItem(n),
  clear: (n) => {
    sessionStorage.removeItem(n);
  },
};

const client = new AlsClient('http://localhost:4000', storage);

await client.clearAuth();

const rsaPK = `MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyZ6wQuYmcVAYw9OomVTt
Qms4UxFVY4vvhBDEmdohbbupFS+R404bTRzX0elLR9/keRFx9xTEk37PDOE5/P7c
OZUZCcJkhIV2pSwKZ+IEUMvKLW0OTx19Zzf6pMPTnlH3o8CSSNlVJfG1u/Z27xFZ
v6P7m6GaBRN2nOO+77QszoQGEYXr52FTL3Mr0Us/4vhb1oLG71KC+PdwKIzm16Y0
fU+C9ZHyESoP2Jv6LABO5taRPWpTtMepXBhF0foqs8bLvJqEMnhOTkLxbdn1Sd9R
iG5S4viWEl4WX4xW5zGhkjq6/laLH/MDMSP0SxERCvKuPiHpZ9rV4uMMGSlZg1is
ICn168DkIy1aUmcSXWb/CkAPNszZtpZOQ6I9l9UZ5BWOW7gARZjVGy864npOYMOY
9BT9OpHaX0V4a2lMreCzS/Pno0URlp+VAp38a6y6I5WBqJ673CPaikJSHalZm6hE
3u+lHHqHU7gnKrtptDYi1pQWVW9aFw+6qz83FYIv6ZBq8wK3cTkkvXjjbxZno7IH
a5X9eZszTMxmS7BHApgOnwDKmX8mL8UPs44SOEKdIjBFrxxZfR+HHCTGxnXh633h
my3rrx90AW7zmokQxmR6sDn1TxHeC2q4KORE/3VjoqnrOZvroc8Mp/ueKDuGVG7C
ceZFvyzIUZN+U40S2y/m5BUCAwEAAQ==`.replace(/\n/g, '');

storage.set('PK_SIG_ANON_CLAIM', rsaPK);

function request(method, isRetry = false) {
  return async (url, body, forceHeaders = {}) => {
    const requestOptions = {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...forceHeaders
      },
      body: JSON.stringify(body),
    };

    const resp = await client.call(url, requestOptions);
    return resp;
  };
}

function renew() {
  return async (url, body, forceHeaders = {}) => {
    const requestOptions = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...forceHeaders
      },
      body: JSON.stringify(body),
    };

    const resp = await client.callAndRenew(url, requestOptions);
    return resp;
  };
}

export const fetchWrapper = {
  login: renew(),
  get: request('GET'),
  post: request('POST'),
  put: request('PUT'),
  delete: request('DELETE'),
};