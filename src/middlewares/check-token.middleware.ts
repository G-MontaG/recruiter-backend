import express = require('express');
import jwt = require('jsonwebtoken');
import Boom = require('boom');
import winston = require('winston');
import moment = require('moment');
import uuid = require('uuid');
import { BaseMiddleware } from './base.middleware';
import { redisConnection } from '../db/redis-connection';
import { privateKey, publicKey, tokenAlg, tokenExp } from '../helpers/constants';
import { Developer } from '../models/developer.model';
import { Recruiter } from '../models/recruiter.model';
import { IUserDocument } from '../models/user.model';

class CheckTokenMiddleware extends BaseMiddleware {
    public middleware() {
        this.checkAuthorizationHeader()
            .then(this.findAuthTokenInLogoutStore.bind(this))
            .then(this.findAuthTokenPreviousSavedStore.bind(this))
            .then(this.verifyAuthToken.bind(this))
            .then(this.nextFn.bind(this))
            .then(this.findTimeToExpireTokenInStore.bind(this))
            .then(this.setAuthTokenInStore.bind(this))
            .catch((err) => {
                if (err.isExist) {
                    return;
                }
                this.errorHandler(err);
            });
    }

    private checkAuthorizationHeader() {
        return new Promise((resolve, reject) => {
            if (!this.req.get('Authorization')) {
                reject(Boom.unauthorized('Authorization token is undefined'));
                return;
            }
            if (!this.req.get('X-CSRF-Token')) {
                reject(Boom.unauthorized('X-CSRF-Token is undefined'));
                return;
            }
            if (this.req.get('Authorization').split(' ')[0] !== 'Bearer') {
                reject(Boom.unauthorized('Authorization token must be bearer type'));
                return;
            }
            if (!this.req.get('Authorization').split(' ')[1]) {
                reject(Boom.unauthorized('Authorization token is undefined'));
                return;
            }
            resolve(this.req.get('Authorization').split(' ')[1]);
        });
    }

    private findAuthTokenInLogoutStore(token: string) {
        return new Promise((resolve, reject) => {
            redisConnection.client.get('LOGOUT-TOKEN:' + token, (err: any, reply: string | null) => {
                if (err) {
                    resolve(token);
                    return;
                }
                if (!reply && reply !== '') {
                    resolve(token);
                } else {
                    reject(Boom.unauthorized('Invalid authorization token'));
                }
            });
        });
    }

    private findAuthTokenPreviousSavedStore(token: string) {
        return new Promise((resolve) => {
            redisConnection.client.get('ACCESS-TOKEN:' + token, (err: any, reply: string | null) => {
                if (err) {
                    resolve({token, isExist: false});
                    return;
                }
                if (!reply) {
                    resolve({token, isExist: false});
                } else {
                    const payload = JSON.parse(reply);
                    this.req.userId = payload.iss;
                    resolve({token, payload, isExist: true});
                }
            });
        });
    }

    private verifyAuthToken(data: { token: string, payload?: any, isExist: boolean }) {
        return new Promise((resolve, reject) => {
            let additionalRules = (payload: any) => {
                if (payload) {
                    if (moment() < moment.unix(payload.iat)) {
                        reject(Boom.unauthorized('Invalid authorization token'));
                        return;
                    }
                    if (payload['user-agent'] !== this.req.get('user-agent')) {
                        reject(Boom.unauthorized('Invalid authorization token'));
                        return;
                    }
                    if (payload.xsrfToken !== this.req.get('X-CSRF-Token')) {
                        reject(Boom.unauthorized('Invalid authorization token'));
                        return;
                    }
                }
            };

            if (!data.isExist) {
                // if access token visit rest api first we verify it
                jwt.verify(data.token, publicKey, (<any>{
                    jwtid: process.env.JWT_ID,
                    algorithms: ['RS512']
                }), (err: any, payload: any): any => {
                    if (err) {
                        if (err.name === 'TokenExpiredError') {
                            // Refresh token logic
                            let decodedPayload: any = jwt.decode(data.token);
                            additionalRules(decodedPayload);
                            return this.getRefreshTokenFromDB(decodedPayload)
                                .then((user: IUserDocument) => {
                                    if (!user) {
                                        throw new Error('User now found');
                                    }
                                    return {user, payload: decodedPayload};
                                })
                                .then(this.compareRefreshTokens.bind(this))
                                .then(this.verifyResultOfComparison.bind(this))
                                .then(this.checkIsRefreshTokenExpired.bind(this))
                                .then(this.generateNewAccessToken.bind(this))
                                .then(this.setNewAccessTokenToResponseHeaders.bind(this))
                                .then((newData) => {
                                    this.req.userId = newData.payload.iss;
                                    resolve(Object.assign({}, data, {payload: newData.payload}));
                                })
                                .catch((err) => {
                                    reject(Boom.unauthorized('Invalid authorization token'));
                                });
                        } else {
                            reject(Boom.unauthorized('Invalid authorization token'));
                            return;
                        }
                    } else {
                        additionalRules(payload);
                        this.req.userId = payload.iss;
                        resolve(Object.assign({}, data, {payload}));
                    }
                });
            } else {
                // if access token already stored we skip huge block of verification logic
                additionalRules(data.payload);
                resolve(data);
            }
        });
    }

    private getRefreshTokenFromDB(payload: any): Promise<IUserDocument> {
        if (payload.sub === 'developer') {
            return Developer.findById(payload.iss).exec();
        }
        return Recruiter.findById(payload.iss).exec();
    }

    private compareRefreshTokens(data: { user: IUserDocument, payload: any }) {
        return Object.assign({}, data, {result: data.user.isRefreshTokenEqual(data.payload.refreshToken)});
    }

    private verifyResultOfComparison(data: { user: IUserDocument, payload: any, result: boolean }) {
        if (!data.result) {
            throw new Error('Refresh tokens are nor equal');
        }
        return data;
    }

    private async checkIsRefreshTokenExpired(data: { user: IUserDocument, payload: any, result: boolean }) {
        if (data.user.isRefreshTokenExpired()) {
            data.user.createRefreshToken();
            await data.user.save();
        }
        return data;
    }

    private async generateNewAccessToken(data: { user: IUserDocument, payload: any, result: boolean }) {
        const xsrfToken = uuid.v4();
        const payload = {
            iss: data.user.id,
            sub: data.payload.sub,
            iat: moment().unix(),
            'user-agent': this.req.headers['user-agent'],
            xsrfToken,
            refreshToken: data.user.refreshToken.value
        };
        const accessToken = jwt.sign(payload, privateKey, {
            algorithm: tokenAlg,
            expiresIn: `${tokenExp}d`,
            jwtid: process.env.JWT_ID
        });
        return Object.assign({}, data, {payload}, {accessToken, xsrfToken});
    }

    private setNewAccessTokenToResponseHeaders(data: { user: IUserDocument, payload: any, result: boolean, accessToken: string, xsrfToken: string }) {
        this.res.setHeader('Authorization', `Bearer ${data.accessToken}`);
        this.res.setHeader('X-CSRF-Token', `${data.xsrfToken}`);
        return data;
    }

    private nextFn(data: any) {
        this.next();
        if (data.isExist) {
            throw data;
        }
        return data;
    }

    private findTimeToExpireTokenInStore(data: { token: string, payload: any, isExist: boolean }) {
        // try to find time to expire token in store
        // if token near to expire time it is no reason to save it in store
        const diff = moment.unix(data.payload.exp).diff(moment()) * 0.001;
        if (diff > 10) {
            return Object.assign({}, data, {exp: diff});
        } else {
            return data;
        }
    }

    private setAuthTokenInStore(data: { token: string, payload: any, isExist: boolean, exp?: string }) {
        return new Promise((resolve) => {
            if (data.exp) {
                redisConnection.client.set('ACCESS-TOKEN:' + data.token, JSON.stringify(data.payload), 'EX', parseInt(data.exp), 'NX', (err: any, reply: 'OK' | void) => {
                    if (err) {
                        winston.log('error', `${this.req.method} ${this.req.path} [RedisError]`);
                    }
                    resolve();
                });
            }
        });
    }
}

export function checkTokenMiddleware(req: express.Request, res: express.Response, next: express.NextFunction) {
    const checkTokenMiddleware = new CheckTokenMiddleware(req, res, next);
    checkTokenMiddleware.middleware();
}
