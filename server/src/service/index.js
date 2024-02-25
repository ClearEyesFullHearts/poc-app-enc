import path from 'node:path';
import express from 'express';
import * as OpenApiValidator from 'express-openapi-validator';
import morgan from 'morgan';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

class Service {
  constructor() {
    this.app = express.Router();
    this.app.options('/*', (req, res) => res.sendStatus(200));
    this.app.use(morgan('combined'));

    this.dir = dirname(fileURLToPath(import.meta.url));
    this.doc = path.join(this.dir, 'spec/openapi.yaml');
  }

  start() {
    this.app.get('/health', (req, res) => {
      res.status(200).send();
    });

    //  Install the OpenApiValidator on your express app
    this.app.use(
      OpenApiValidator.middleware({
        apiSpec: this.doc,
        validateApiSpec: true,
        validateResponses: true, // default false
        // Provide the base path to the operation handlers directory
        operationHandlers: path.join(this.dir, 'controller'), // default false
      }),
    );

    this.app.use((req, res) => {
      res.status(404).send("Sorry can't find that!");
    });

    return this.app;
  }
}

export default Service;
