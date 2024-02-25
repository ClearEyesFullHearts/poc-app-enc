import express from 'express';
import Service from './src/service/index.js';
import Auth from './src/endpoint/index.js';

const app = express();
app.use(express.text());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.post('/claim', Auth.anonClaim);

const api = new Service().start();
app.post('/api', Auth.interceptor(api));

app.listen(4000, () => {
  console.log('Your server is listening on port 4000');
});
