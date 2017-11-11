import fs = require('fs');
import path = require('path');
import mongoose = require('mongoose');
mongoose.Promise = global.Promise;
import winston = require('winston');

// connection string format: 'mongodb://username:password@localhost:27017/test';
class MongodbConnection {
    private readonly connectionUrlParts: string[];
    private readonly connectionUrl: string;

    private privateKey = fs.readFileSync(path.resolve('./environment/mongodb.pem'));
    private readonly connectionOptions = {
        useMongoClient: true,
        keepAlive: 30000,
        connectTimeoutMS: 0,
        socketTimeoutMS: 0,
        autoReconnect: true,
        reconnectTries: 30,
        reconnectInterval: 3000,
        promiseLibrary: global.Promise,

        ssl: true,
        sslValidate: false,
        sslCert: this.privateKey,

        user: process.env.MONGO_USER,
        pass: process.env.MONGO_PASSWORD
    };

    constructor() {
        this.connectionUrlParts = [];
        this.connectionUrlParts.push('mongodb://');

        this.connectionUrlParts.push(process.env.MONGO_HOST + ':' +
            process.env.MONGO_PORT + '/' +
            process.env.MONGO_DB_NAME + '?authSource=admin');
        this.connectionUrl = this.connectionUrlParts.join('');

        this.subscribeToMongoEvents(mongoose.connection);
        mongoose.connect(this.connectionUrl, this.connectionOptions)
            .catch((err: any) => {
                winston.log('error', err);
            })
    }

    private subscribeToMongoEvents(connection: any) {
        connection.on('connected', () => {
            winston.log('info', `Mongoose connected`);
        });
        connection.on('open', () => {
            winston.log('info', `Mongoose connection opened`);
        });
        connection.on('disconnecting', () => {
            winston.log('info', 'Mongoose disconnecting');
        });
        connection.on('db: disconnected', () => {
            winston.log('info', 'Mongoose disconnected');
        });
        connection.on('close', () => {
            winston.log('info', 'Mongoose connection closed');
        });
        connection.on('reconnected', () => {
            winston.log('info', 'Mongoose reconnected');
        });
        connection.on('error', (error: any) => {
            winston.log('error', error);
        });
    }
}

export const mongodbConnection = new MongodbConnection();
