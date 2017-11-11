import path = require('path');
import dotenv = require('dotenv');
dotenv.config({path: path.resolve('compiled-test-bdd/environment/.env')});

import uuid = require('uuid');
process.env.JWT_ID = uuid.v4();

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

import '../src/db';
import '../src/models';
import './middlewares';
import './controllers/auth';
import './controllers/api';
