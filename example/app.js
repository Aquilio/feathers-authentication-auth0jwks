import feathers from "@feathersjs/feathers";
import express from "@feathersjs/express";
import configuration from '@feathersjs/configuration';
import { errorHandler } from "@feathersjs/express";
import authentication from './authentication';

const NeDB = require('nedb');
const service = require('feathers-nedb');

const Model = new NeDB({
  filename: `${__dirname}/data/users.db`,
  autoload: true
});

const app = express(feathers())
  .configure(configuration())
  .configure(express.rest())
  .use(express.json())
  .use(express.urlencoded({ extended: true }))
  .configure(authentication);

  app.use('/', express.static(app.get('public')))
  .use('/users', service({ Model }));

app.use(errorHandler());

module.exports = app.listen(app.get('port'));

console.log(`Feathers Authentication with Auth0JWKS running on ${app.get('host')}:${app.get('port')}`);
