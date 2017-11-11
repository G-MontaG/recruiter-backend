import path = require('path');

import express = require('express');
import bodyParser = require('body-parser');
import cookieParser = require('cookie-parser');
import cors = require('cors');
import helmet = require('helmet');
import dotenv = require('dotenv');

import winston = require('winston');
import Raven = require('raven');
import mongoose = require('mongoose');

dotenv.config({path: path.resolve('./environment/.env')});

// import multer = require('multer');
// const upload = multer({dest: path.join(__dirname, '../uploads')});

import './db';
import './models';
import { developerApiRouter, recruiterApiRouter } from './controllers/api/api.router';
import { developerAuthRouter, recruiterAuthRouter } from './controllers/auth/auth.router';
import { redisConnection } from './db/redis-connection';

const publicDir = path.join(__dirname, 'public');

class Server {
    public app: express.Application;
    public connection: any;

    constructor() {
        this.app = express();
        this.app.set('port', process.env.SERVER_PORT || 3001);
        this.app.use(bodyParser.json());
        this.app.use(bodyParser.urlencoded({extended: true}));
        this.app.use(cookieParser());
        // use ngx_http_gzip_module instead of compression
        this.app.use(helmet());
        this.app.use(cors());

        this.app.use(express.static(publicDir));

        this.configureRoutes();
        this.configureErrorHandler();

        this.connection = this.app.listen(this.app.get('port'), () => {
            winston.log('info', `Server listening on port ${this.app.get('port')} in ${this.app.get('env')} mode`);
            if(process.send) {
                process.send('ready');
            }
        });

        process.on('SIGINT', this._gracefulShutdown.bind(this));
        process.on('SIGTERM', this._gracefulShutdown.bind(this));
        process.on('uncaughtException', this.uncaughtException.bind(this));
        process.on('unhandledRejection', this.unhandledRejection.bind(this));
    }

    private addNamespace(namespace: string, router: any) {
        this.app.use(namespace, router);
    }

    private configureRoutes() {
        this.addNamespace('/auth/developer', developerAuthRouter.routes);
        this.addNamespace('/auth/recruiter', recruiterAuthRouter.routes);

        this.addNamespace('/api/developer', developerApiRouter.routes);
        this.addNamespace('/api/recruiter', recruiterApiRouter.routes);
    }

    private configureErrorHandler() {
        if (process.env.NODE_ENV === 'production') {
            Raven.config(process.env.SENTRY,
                {
                    release: process.env.VERSION,
                    environment: process.env.NODE_ENV,
                    parseUser: function (req) {
                        return {
                            userId: req.userId
                        };
                    },
                    autoBreadcrumbs: {
                        'console': false,
                        'http': true,
                    }
                })
                .install();
            this.app.use(Raven.requestHandler());
            this.app.use(Raven.errorHandler());
        }

        this.app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
            winston.log('error', `${req.protocol} ${req.method} ${req.originalUrl} [${err.status || err.code}] - ${err.message}`);
            if(err.stack) {
                winston.log('error', err.stack);
            }
            res.status(err.status || 500).send({
                message: err.message || err.name,
                error: err.toString()
            });
        });
    }

    private _gracefulShutdown() {
        if (process.env.NODE_ENV === 'development') {
            return process.exit(1);
        }

        winston.log('info', 'Closing server. Get SIGINT/SIGTERM signal');
        const cleanUp = () => {
            return new Promise((resolve) => {
                mongoose.disconnect().then(() => {
                    redisConnection.client.quit(() => {
                        resolve();
                    });
                });
            });
        };

        this.connection.close(() => {
            cleanUp().then(() => {
                winston.log('info', 'Server closed');
                return process.exit();
            }).catch((err) => {
                winston.log('info', 'Server closed with errors');
                winston.log('info', err);
                return process.exit();
            });

        });

        setTimeout(() => {
            cleanUp().then(() => {
                winston.log('warning', 'Server closed forced');
                return process.exit(1);
            }).catch((err) => {
                winston.log('warning', 'Server closed forced with errors');
                winston.log('warning', err);
                return process.exit(1);
            });
        }, 5000);

        setTimeout(() => {
            winston.log('error', 'Server was destroy without closing connection');
            return process.exit(1);
        }, 10000);
    }

    private uncaughtException(err: any) {
        if (process.env.NODE_ENV === 'production') {
            Raven.captureException(err);
        }
        winston.log('error', err.stack);
        process.exit(1);
    }

    private unhandledRejection(err: any) {
        if (process.env.NODE_ENV === 'production') {
            Raven.captureException(err);
        }
        winston.log('error', err.stack);
        process.exit(1);
    }
}

const server = new Server();


