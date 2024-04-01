import fs from 'node:fs';
import crypto from 'node:crypto';
import express from 'express';
import morgan from 'morgan';
import ExpressEndpoint from '@protocol/endpoint';
import { ProtocolError } from '@protocol/errors';
import Service from './src/service/index.js';

const pem = fs.readFileSync('./data/rsaSK.pem');
process.env.MASTER_KEY_AUTH = crypto.randomBytes(32).toString('base64url');
process.env.RSA_KEY_SIGNATURE = pem;

const app = express();
app.use((req, res, next) => {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,OPTION',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Content-Length, X-Anon-Authorization, X-Signature-Request',
    'Access-Control-Expose-Headers': '*',
  };
  Object.keys(corsHeaders).forEach((h) => {
    res.header(h, corsHeaders[h]);
  });
  next();
});
app.options('/*', (req, res) => res.sendStatus(200));
app.use(morgan('dev'));
const router = new Service().start();

app.use(express.text());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const endpoints = new ExpressEndpoint();

app.post('/claim', (req, res, next) => {
  endpoints.anonymous(req, res, next);
});
app.post('/protected', (req, res, next) => {
  endpoints.identified(req, res, next);
}, router);

app.use((req, res) => {
  res.status(404).send("Sorry can't find that!");
});

app.use((err, req, res, next) => {
  console.log('ERROR\n', err);
  if (err instanceof ProtocolError) {
    if (process.env.NODE_ENV === 'production') {
      return res.status(401).end();
    }
    return res.status(401).json(err);
  }
  return res.status(500).json(err);
});

app.listen(4000, () => {
  console.log('Your server is listening on port 4000');
});
