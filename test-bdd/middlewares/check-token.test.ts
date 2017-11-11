import chai = require('chai');
import chaiHttp = require('chai-http');
import jwt = require('jsonwebtoken');
import moment = require('moment');
import { assert } from 'chai';
import { authObject, server } from '../helpers/constants';
import { redisConnection } from '../../src/db/redis-connection';
import { Developer } from '../../src/models/developer.model';
import { privateKey, tokenAlg } from '../../src/helpers/constants';

chai.use(chaiHttp);

describe('Check authorization token middleware', () => {
    let userId;
    let payload;
    before((done) => {
        Developer.remove({email: 'arthur@mailinator.com'}, (err) => {
            chai.request(server)
                .post('/auth/developer/sign-up')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST'
                })
                .end((err, res) => {
                    authObject.developer.accessToken = res.body.accessToken;
                    authObject.developer.xsrfToken = res.body.xsrfToken;
                    payload = jwt.decode(authObject.developer.accessToken);

                    Developer.findOne({email: 'arthur@mailinator.com'}, (err, user) => {
                        userId = user.id;
                        done();
                    });
                });
        });
    });

    it('it should return unauthorized error if request without authorization token', (done) => {
        chai.request(server)
            .post('/auth/developer/verify-email')
            .end((err, res) => {
                assert.equal(res.status, 401, 'should be status 401');
                assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                assert.equal(res.body.message, 'Authorization token is undefined', 'should be \'Authorization token is undefined\' message');
                done();
            });
    });
    it('it should return unauthorized error if request with wrong authorization type', (done) => {
        chai.request(server)
            .post('/auth/developer/verify-email')
            .set('Authorization', 'Bear fakeFake')
            .set('X-CSRF-Token', authObject.developer.xsrfToken)
            .end((err, res) => {
                assert.equal(res.status, 401, 'should be status 401');
                assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                assert.equal(res.body.message, 'Authorization token must be bearer type', 'should be \'Authorization token must be bearer type\' message');
                done();
            });
    });
    it('it should return unauthorized error if request with wrong authorization token', (done) => {
        chai.request(server)
            .post('/auth/developer/verify-email')
            .set('Authorization', 'Bearer fakeFake')
            .set('X-CSRF-Token', authObject.developer.xsrfToken)
            .end((err, res) => {
                assert.equal(res.status, 401, 'should be status 401');
                assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                assert.equal(res.body.message, 'Invalid authorization token', 'should be \'Invalid authorization token\' message');
                done();
            });
    });
    it('it should return unauthorized error if request with wrong xsrf token', (done) => {
        chai.request(server)
            .post('/auth/developer/verify-email')
            .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
            .set('X-CSRF-Token', 'fakeFake')
            .end((err, res) => {
                assert.equal(res.status, 401, 'should be status 401');
                assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                assert.equal(res.body.message, 'Invalid authorization token', 'should be \'Invalid authorization token\' message');
                setTimeout(() => {
                    redisConnection.client.get('ACCESS-TOKEN:' + authObject.developer.accessToken, (err: any, reply: string | null) => {
                        assert.notExists(err, 'redis work');
                        assert.notExists(reply, 'token not set in redis database');
                        done();
                    });
                }, 100);
            });
    });
    it('it should return okey if authorization token is okey', (done) => {
        chai.request(server)
            .post('/auth/developer/verify-email')
            .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
            .set('X-CSRF-Token', authObject.developer.xsrfToken)
            .end((err, res: any) => {
                assert.notEqual(res.status, 401, 'should be status not 401');
                assert.notExists(res.headers['authorization'], 'should not be header with authorization');
                setTimeout(() => {
                    redisConnection.client.get('ACCESS-TOKEN:' + authObject.developer.accessToken, (err: any, reply: string | null) => {
                        assert.notExists(err, 'redis work');
                        assert.exists(reply, 'token set in redis database');
                        redisConnection.client.ttl('ACCESS-TOKEN:' + authObject.developer.accessToken, (err: any, reply: number) => {
                            assert.isAtMost(+reply, 3600, 'less or equal to 3600');
                            done();
                        });
                    });
                }, 100);
            });
    });
    it('it should return unauthorized error if request with wrong xsrf token, even if it store in redis', (done) => {
        redisConnection.client.get('ACCESS-TOKEN:' + authObject.developer.accessToken, (err: any, reply: string | null) => {
            assert.notExists(err, 'redis work');
            assert.exists(reply, 'token set in redis database');
            chai.request(server)
                .post('/auth/developer/verify-email')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', 'fakeFake')
                .end((err, res) => {
                    assert.equal(res.status, 401, 'should be status 401');
                    assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                    assert.equal(res.body.message, 'Invalid authorization token', 'should be \'Invalid authorization token\' message');
                    done();
                });
        });
    });
    it('it should return okey with less expire time in redis if token near to expire', (done) => {
        const accessToken = jwt.sign({
            iss: userId,
            sub: 'developer',
            iat: moment().unix(),
            'user-agent': 'node-superagent/2.3.0',
            refreshToken: payload.refreshToken + 'fake',
            xsrfToken: payload.xsrfToken
        }, privateKey, {
            algorithm: tokenAlg,
            expiresIn: `20m`,
            jwtid: '16dc7573-d27b-4e0b-96ff-6277429ed1d1'
        });
        chai.request(server)
            .post('/auth/developer/verify-email')
            .set('Authorization', `Bearer ${accessToken}`)
            .set('X-CSRF-Token', payload.xsrfToken)
            .end((err, res) => {
                assert.notEqual(res.status, 401, 'should be status not 401');
                setTimeout(() => {
                    redisConnection.client.get('ACCESS-TOKEN:' + accessToken, (err: any, reply: string | null) => {
                        assert.notExists(err, 'redis work');
                        assert.exists(reply, 'token set in redis database');
                        redisConnection.client.ttl('ACCESS-TOKEN:' + accessToken, (err: any, reply: number) => {
                            assert.isAtMost(+reply, 1200, 'less or equal to 1200');
                            done();
                        });
                    });
                }, 100);
            });
    });
    it('it should return unauthorized error if token expire and refresh token not equal', (done) => {
        const accessToken = jwt.sign({
            iss: userId,
            sub: 'developer',
            iat: moment().unix(),
            'user-agent': 'node-superagent/2.3.0',
            refreshToken: payload.refreshToken + 'fake',
            xsrfToken: payload.xsrfToken
        }, privateKey, {
            algorithm: tokenAlg,
            expiresIn: `1s`,
            jwtid: '16dc7573-d27b-4e0b-96ff-6277429ed1d1'
        });
        setTimeout(() => {
            chai.request(server)
                .post('/auth/developer/verify-email')
                .set('Authorization', `Bearer ${accessToken}`)
                .set('X-CSRF-Token', payload.xsrfToken)
                .end((err, res) => {
                    assert.equal(res.status, 401, 'should be status not 401');
                    assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                    assert.equal(res.body.message, 'Invalid authorization token', 'should be \'Invalid authorization token\' message');
                    done();
                });
        }, 1001);
    });
    it('it should return okey if token expire but refresh token is okey', (done) => {
        const createTime = moment().unix();
        const accessToken = jwt.sign({
            iss: userId,
            sub: 'developer',
            iat: createTime,
            'user-agent': 'node-superagent/2.3.0',
            refreshToken: payload.refreshToken,
            xsrfToken: payload.xsrfToken
        }, privateKey, {
            algorithm: tokenAlg,
            expiresIn: `1s`,
            jwtid: '16dc7573-d27b-4e0b-96ff-6277429ed1d1'
        });
        setTimeout(() => {
            chai.request(server)
                .post('/auth/developer/verify-email')
                .set('Authorization', `Bearer ${accessToken}`)
                .set('X-CSRF-Token', payload.xsrfToken)
                .end((err, res: any) => {
                    assert.notEqual(res.status, 401, 'should be status not 401');
                    assert.exists(res.get('x-csrf-token'), 'should be header with xsrfToken');
                    assert.notEqual(res.get('x-csrf-token'), payload.xsrfToken, 'should be header xsrfToken must not be equal with previous');
                    assert.exists(res.get('Authorization'), 'should be header with authorization');
                    assert.notEqual(res.get('Authorization'), accessToken, 'should be header accessToken must not be equal with previous');

                    const decodedPayload: any = jwt.decode(res.get('Authorization').split(' ')[1]);
                    assert.equal(decodedPayload.refreshToken, payload.refreshToken, 'should be new token with same refresh token');
                    assert.isTrue(moment.unix(decodedPayload.iat) > moment.unix(createTime), 'should be new creation time');
                    Developer.findOne({email: 'arthur@mailinator.com'}, (err, user) => {
                        assert.equal(user.refreshToken.value, decodedPayload.refreshToken, 'should be refresh token equal');
                        done();
                    });
                });
        }, 1001);
    });
    it('it should return okey if token expire but refresh token is okey (with changing refresh token to new if it expire to)', (done) => {
        Developer.findOneAndUpdate({email: 'arthur@mailinator.com'},
            {refreshToken: { value: payload.refreshToken, exp: moment().toDate()}},
            (err, user) => {
                const createTime = moment().unix();
                const accessToken = jwt.sign({
                    iss: userId,
                    sub: 'developer',
                    iat: createTime,
                    'user-agent': 'node-superagent/2.3.0',
                    refreshToken: payload.refreshToken,
                    xsrfToken: payload.xsrfToken
                }, privateKey, {
                    algorithm: tokenAlg,
                    expiresIn: `1s`,
                    jwtid: '16dc7573-d27b-4e0b-96ff-6277429ed1d1'
                });
                setTimeout(() => {
                    chai.request(server)
                        .post('/auth/developer/verify-email')
                        .set('Authorization', `Bearer ${accessToken}`)
                        .set('X-CSRF-Token', payload.xsrfToken)
                        .end((err, res: any) => {
                            assert.notEqual(res.status, 401, 'should be status not 401');
                            assert.exists(res.get('x-csrf-token'), 'should be header with xsrfToken');
                            assert.notEqual(res.get('x-csrf-token'), payload.xsrfToken, 'should be header xsrfToken must not be equal with previous');
                            assert.exists(res.get('Authorization'), 'should be header with authorization');
                            assert.notEqual(res.get('Authorization'), accessToken, 'should be header accessToken must not be equal with previous');

                            const decodedPayload: any = jwt.decode(res.get('Authorization').split(' ')[1]);
                            assert.notEqual(decodedPayload.refreshToken, payload.refreshToken, 'should be new token with new refresh token');
                            assert.isTrue(moment.unix(decodedPayload.iat) > moment.unix(createTime), 'should be new creation time');
                            Developer.findOne({email: 'arthur@mailinator.com'}, (err, user) => {
                                assert.equal(user.refreshToken.value, decodedPayload.refreshToken, 'should be refresh token equal');
                                assert.notEqual(user.refreshToken.value, payload.refreshToken, 'should not be refresh token equal');
                                done();
                            });
                        });
                }, 1001);
        });
    });
});
