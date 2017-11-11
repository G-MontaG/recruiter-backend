import chai = require('chai');
import chaiHttp = require('chai-http');
import moment = require('moment');
import { assert } from 'chai';
import { authObject, server } from '../../helpers/constants';
import { redisConnection } from '../../../src/db/redis-connection';

chai.use(chaiHttp);

describe('Logout', () => {
    it('it should return unauthorized error if request without authorization token', (done) => {
        chai.request(server)
            .get('/auth/developer/logout')
            .end((err, res) => {
                assert.equal(res.status, 401, 'should be status 401');
                assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                assert.equal(res.body.message, 'Authorization token is undefined', 'should be \'Authorization token is undefined\' message');
                done();
            });
    });
    it('it should return okey if user is logout', (done) => {
        const checkIsTokenExistInDbBefore = () => {
            return new Promise((resolve, reject) => {
                redisConnection.client.get('ACCESS-TOKEN:' + authObject.developer.accessToken, (err: any, reply: string | null) => {
                    resolve(JSON.parse(reply));
                });
            })
        };

        const logoutRequest = (payload) => {
            return new Promise((resolve) => {
                chai.request(server)
                    .get('/auth/developer/logout')
                    .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                    .set('X-CSRF-Token', authObject.developer.xsrfToken)
                    .end((err, res) => {
                        assert.equal(res.status, 200, 'should be status 200');
                        setTimeout(() => {
                            resolve(payload);
                        }, 100);
                    });
            });
        };

        const checkIsTokenRemoved = (payload) => {
            return new Promise((resolve) => {
                redisConnection.client.get('ACCESS-TOKEN:' + authObject.developer.accessToken, (err: any, reply: string | null) => {
                    assert.notExists(err, 'redis work');
                    assert.notExists(reply, 'token was removed from redis database');
                    resolve(payload);
                });
            });
        };

        const checkIsTokenSetAsLogout = (payload) => {
            return new Promise((resolve) => {
                redisConnection.client.get('LOGOUT-TOKEN:' + authObject.developer.accessToken, (err: any, reply: string) => {
                    assert.notExists(err, 'redis work');
                    assert.exists(reply, 'token stored as logout in redis database');
                    assert.isEmpty(reply, 'token stored without any information');
                    resolve(payload);
                });
            });
        };

        const checkExpireTime = (payload) => {
            return new Promise((resolve) => {
                redisConnection.client.ttl('LOGOUT-TOKEN:' + authObject.developer.accessToken, (err: any, reply: number) => {
                    assert.isAtLeast(reply, parseInt((moment(payload.exp).diff(moment()) * 0.001).toString()),
                        `expire time seconds more then seconds from now`);
                    assert.isAtMost(reply, 3600, 'expire time below then 1 hour');
                    done();
                });
            });
        };

        checkIsTokenExistInDbBefore()
            .then(logoutRequest.bind(this))
            .then(checkIsTokenRemoved.bind(this))
            .then(checkIsTokenSetAsLogout.bind(this))
            .then(checkExpireTime.bind(this))
            .catch((err) => console.log(err));
    });
    it('it should return unauthorized error if request with logout authorization token', (done) => {
        chai.request(server)
            .post('/auth/developer/verify-email')
            .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
            .set('X-CSRF-Token', authObject.developer.xsrfToken)
            .end((err, res) => {
                assert.equal(res.status, 401, 'should be status 401');
                assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                assert.equal(res.body.message, 'Invalid authorization token', 'should be \'Invalid authorization token\' message');
                done();
            });
    });
});
