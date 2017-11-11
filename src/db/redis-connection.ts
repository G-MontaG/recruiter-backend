import redis = require('redis');
import winston = require('winston');

// connection string format: 'mongodb://username:password@localhost:27017/test';
class RedisConnection {
    public readonly client: any;
    private readonly connectionUrlParts: string[];
    private readonly connectionUrl: string;

    private readonly connectionOptions = {
        password: process.env.REDIS_PASSWORD,
        retry_strategy: function (options: any) {
            // if (options.error && options.error.code === 'ECONNREFUSED') {
            //     // End reconnecting on a specific error and flush all commands with
            //     // a individual error
            //     return new Error('The server refused the connection');
            // }
            if (options.total_retry_time > 3000 * 30 * 60) {
                // End reconnecting after a specific timeout and flush all commands
                // with a individual error
                return new Error('Retry time exhausted');
            }
            if (options.attempt > 30) {
                // End reconnecting with built in error
                return undefined;
            }
            // reconnect after
            return 3000;
        }
    };

    constructor() {
        this.connectionUrlParts = [];
        this.connectionUrlParts.push('redis://');

        this.connectionUrlParts.push(process.env.REDIS_HOST + ':' +
            process.env.REDIS_PORT + '/' +
            process.env.REDIS_DB_NAME);
        this.connectionUrl = this.connectionUrlParts.join('');

        this.client = redis.createClient(this.connectionUrl, this.connectionOptions);
        this.subscribeToRedisEvents();
    }

    private subscribeToRedisEvents() {
        this.client.on('ready', () => {
            winston.log('info', `Redis ready`);
            this.client.auth(process.env.REDIS_PASSWORD);
        });
        this.client.on('connect', () => {
            winston.log('info', `Redis connected`);
        });
        this.client.on('reconnecting', (data: any) => {
            winston.log('info', 'Redis reconnecting' + JSON.stringify(data));
        });
        this.client.on('error', (error: any) => {
            const errorType = ['ReplyError', 'AbortError', 'ParserError', 'AggregateError', 'RedisError'].find((type) => {
                return error instanceof redis[type];
            });
            winston.log('error', `[${errorType || 'RedisError'}] ${error.command} - ${error.args}`);
        });
        this.client.on('end', () => {
            winston.log('info', 'Redis connection closed');
        });
        this.client.on('warning', (warning: any) => {
            winston.log('warning', warning);
        });
    }
}

export const redisConnection = new RedisConnection();
