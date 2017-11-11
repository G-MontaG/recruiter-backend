import chai = require('chai');
import chaiHttp = require('chai-http');
import { assert } from 'chai';
import moment = require('moment');
import { authObject, server } from '../../helpers/constants';
import { Developer } from '../../../src/models/developer.model';
import { IUserDocument } from '../../../src/models/user.model';
import { Recruiter } from '../../../src/models/recruiter.model';
import { redisConnection } from '../../../src/db/redis-connection';

chai.use(chaiHttp);

describe('Reset password, check token from email, for developers', () => {
    let savedUser: IUserDocument;

    before((done) => {
        Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
            .then((user: IUserDocument) => {
                savedUser = user;
                done();
            });
    });

    describe('/auth/developer/reset-token', () => {
        it('it should return unauthorized error if request without authorization token', (done) => {
            chai.request(server)
                .post('/auth/developer/reset-token')
                .end((err, res) => {
                    assert.equal(res.status, 401, 'should be status 401');
                    assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                    assert.equal(res.body.message, 'Authorization token is undefined', 'should be \'Authorization token is undefined\' message');
                    done();
                });
        });
        it('it should return validation error on to short password', (done) => {
            chai.request(server)
                .post('/auth/developer/reset-token')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
                    token: savedUser.resetPasswordToken.value,
                    oldPassword: 'testTEST',
                    password: 'test',
                    confirmPassword: 'test'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'password', 'should be invalid password error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return validation error on to long password', (done) => {
            chai.request(server)
                .post('/auth/developer/reset-token')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
                    token: savedUser.resetPasswordToken.value,
                    oldPassword: 'testTEST',
                    password: 'testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest',
                    confirmPassword: 'testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'password', 'should be invalid password error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return validation error on not equal password and confirmPassword', (done) => {
            chai.request(server)
                .post('/auth/developer/reset-token')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
                    token: savedUser.resetPasswordToken.value,
                    oldPassword: 'testTEST',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2fake'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'confirmPassword', 'should be invalid confirmPassword error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return validation error on to short old password', (done) => {
            chai.request(server)
                .post('/auth/developer/reset-token')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
                    token: savedUser.resetPasswordToken.value,
                    oldPassword: 'test',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'oldPassword', 'should be invalid oldPassword error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return validation error on to long old password', (done) => {
            chai.request(server)
                .post('/auth/developer/reset-token')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
                    token: savedUser.resetPasswordToken.value,
                    oldPassword: 'testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'oldPassword', 'should be invalid oldPassword error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        // it('it should return validation error on equal old password and new password', (done) => {
        //     chai.request(server)
        //         .post('/auth/developer/reset-token')
        //         .set('Authorization', `Bearer ${authObject.developer}`)
        //         .send({
        //             oldPassword: 'testTEST',
        //             password: 'testTEST',
        //             confirmPassword: 'testTEST',
        //             token: savedUser.resetPasswordToken.value
        //         })
        //         .end((err, res) => {
        //             assert.equal(res.status, 400, 'should be status 400');
        //             assert.equal(res.body.error[0].path, 'password', 'should be invalid password error');
        //             assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
        //             done();
        //         });
        // });
        it('it should return validation error on to long token', (done) => {
            chai.request(server)
                .post('/auth/developer/reset-token')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
                    oldPassword: 'testTEST',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2',
                    token: `${savedUser.resetPasswordToken.value}fake`
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'token', 'should be invalid token error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return validation error on to short token', (done) => {
            chai.request(server)
                .post('/auth/developer/reset-token')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
                    oldPassword: 'testTEST',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2',
                    token: savedUser.resetPasswordToken.value.slice(0, 6)
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'token', 'should be invalid token error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return error on wrong token', (done) => {
            chai.request(server)
                .post('/auth/developer/reset-token')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
                    oldPassword: 'testTEST',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2',
                    token: 'testTest'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                    assert.equal(res.body.message, 'Token is wrong', 'should be \'Token is wrong\' message');
                    done();
                });
        });
        it('it should return error on expired token', (done) => {
            Developer.findOneAndUpdate({email: 'arthur@mailinator.com'},
                {
                    resetPasswordToken: {
                        value: savedUser.resetPasswordToken.value,
                        exp: moment('01/01/1992', 'MM/DD/YYYY').toDate()
                    }
                }, (err, user) => {
                    chai.request(server)
                        .post('/auth/developer/reset-token')
                        .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                        .set('X-CSRF-Token', authObject.developer.xsrfToken)
                        .send({
                            oldPassword: 'testTEST',
                            password: 'testTEST2',
                            confirmPassword: 'testTEST2',
                            token: savedUser.resetPasswordToken.value
                        })
                        .end((err, res) => {
                            assert.equal(res.status, 400, 'should be status 400');
                            assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                            assert.equal(res.body.message, 'Token expired', 'should be \'Token expired\' message');

                            Developer.findOneAndUpdate({email: 'arthur@mailinator.com'},
                                {
                                    resetPasswordToken: {
                                        value: savedUser.resetPasswordToken.value,
                                        exp: savedUser.resetPasswordToken.exp
                                    }
                                }, (err, user) => {
                                    done();
                                });
                        });
                });
        });
        it('it should return okey if token is okey', (done) => {
            chai.request(server)
                .post('/auth/developer/reset-token')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
                    oldPassword: 'testTEST',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2',
                    token: savedUser.resetPasswordToken.value
                })
                .end((err, res) => {
                    assert.equal(res.status, 200, 'should be status 200');
                    assert.equal(res.body.message, 'Password has been changed', 'should be \'Password has been changed\' message');

                    assert.exists(res.body.accessToken, 'should have the accessToken field');
                    assert.isString(res.body.accessToken, 'accessToken should be a string');
                    assert.isAtLeast(res.body.accessToken.length, 300, 'accessToken should be at least 300 long string');

                    assert.exists(res.body.xsrfToken, 'should have the xsrfToken field');
                    assert.isString(res.body.xsrfToken, 'xsrfToken should be a string');
                    Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: any) => {
                            assert.notExists(user.resetPasswordToken, 'should delete emailVerifyToken field');
                            assert.notEqual(savedUser.hash, user.hash, 'should another password hash');
                            assert.notEqual(savedUser.salt, user.salt, 'should another password salt');
                            setTimeout(() => {
                                redisConnection.client.get('LOGOUT-TOKEN:' + authObject.developer.accessToken, (err: any, reply: string) => {
                                    assert.notExists(err, 'redis work');
                                    assert.exists(reply, 'token stored as logout in redis database');
                                    assert.isEmpty(reply, 'token stored without any information');

                                    authObject.developer.accessToken = res.body.accessToken;
                                    authObject.developer.xsrfToken = res.body.xsrfToken;
                                    done();
                                });
                            }, 100);
                        });
                });
        });
        it('it should return error always if user somehow can access to this route without using previously /reset/email', (done) => {
            chai.request(server)
                .post('/auth/developer/reset-token')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
                    oldPassword: 'testTEST',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2',
                    token: 'fakeFake'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                    assert.equal(res.body.message, 'Token wasn\'t send', 'should be \'Token wasn\'t send\' message');

                    Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: IUserDocument) => {
                            assert.notExists(user.resetPasswordToken, 'should delete resetPasswordToken field');
                            done();
                        });
                });
        });
    });
});

describe('Reset password, check token from email, for recruiters', () => {
    let savedUser: IUserDocument;

    before((done) => {
        Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
            .then((user: IUserDocument) => {
                savedUser = user;
                done();
            });
    });

    describe('/auth/recruiter/reset-token', () => {
        it('it should return unauthorized error if request without authorization token', (done) => {
            chai.request(server)
                .post('/auth/recruiter/reset-token')
                .end((err, res) => {
                    assert.equal(res.status, 401, 'should be status 401');
                    assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                    assert.equal(res.body.message, 'Authorization token is undefined', 'should be \'Authorization token is undefined\' message');
                    done();
                });
        });
        it('it should return validation error on to short password', (done) => {
            chai.request(server)
                .post('/auth/recruiter/reset-token')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
                    token: savedUser.resetPasswordToken.value,
                    oldPassword: 'testTEST',
                    password: 'test',
                    confirmPassword: 'test'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'password', 'should be invalid password error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return validation error on to long password', (done) => {
            chai.request(server)
                .post('/auth/recruiter/reset-token')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
                    token: savedUser.resetPasswordToken.value,
                    oldPassword: 'testTEST',
                    password: 'testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest',
                    confirmPassword: 'testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'password', 'should be invalid password error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return validation error on not equal password and confirmPassword', (done) => {
            chai.request(server)
                .post('/auth/recruiter/reset-token')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
                    token: savedUser.resetPasswordToken.value,
                    oldPassword: 'testTEST',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2fake'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'confirmPassword', 'should be invalid confirmPassword error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return validation error on to short old password', (done) => {
            chai.request(server)
                .post('/auth/recruiter/reset-token')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
                    token: savedUser.resetPasswordToken.value,
                    oldPassword: 'test',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'oldPassword', 'should be invalid oldPassword error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return validation error on to long old password', (done) => {
            chai.request(server)
                .post('/auth/recruiter/reset-token')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
                    token: savedUser.resetPasswordToken.value,
                    oldPassword: 'testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'oldPassword', 'should be invalid oldPassword error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        // it('it should return validation error on equal old password and new password', (done) => {
        //     chai.request(server)
        //         .post('/auth/developer/reset-token')
        //         .set('Authorization', `Bearer ${authObject.developer}`)
        //         .send({
        //             oldPassword: 'testTEST',
        //             password: 'testTEST',
        //             confirmPassword: 'testTEST',
        //             token: savedUser.resetPasswordToken.value
        //         })
        //         .end((err, res) => {
        //             assert.equal(res.status, 400, 'should be status 400');
        //             assert.equal(res.body.error[0].path, 'password', 'should be invalid password error');
        //             assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
        //             done();
        //         });
        // });
        it('it should return validation error on to long token', (done) => {
            chai.request(server)
                .post('/auth/recruiter/reset-token')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
                    oldPassword: 'testTEST',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2',
                    token: `${savedUser.resetPasswordToken.value}fake`
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'token', 'should be invalid token error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return validation error on to short token', (done) => {
            chai.request(server)
                .post('/auth/recruiter/reset-token')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
                    oldPassword: 'testTEST',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2',
                    token: savedUser.resetPasswordToken.value.slice(0, 6)
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'token', 'should be invalid token error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return error on wrong token', (done) => {
            chai.request(server)
                .post('/auth/recruiter/reset-token')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
                    oldPassword: 'testTEST',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2',
                    token: 'testTest'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                    assert.equal(res.body.message, 'Token is wrong', 'should be \'Token is wrong\' message');
                    done();
                });
        });
        it('it should return error on expired token', (done) => {
            Recruiter.findOneAndUpdate({email: 'arthur@mailinator.com'},
                {
                    resetPasswordToken: {
                        value: savedUser.resetPasswordToken.value,
                        exp: moment('01/01/1992', 'MM/DD/YYYY').toDate()
                    }
                }, (err, user) => {
                    chai.request(server)
                        .post('/auth/recruiter/reset-token')
                        .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                        .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                        .send({
                            oldPassword: 'testTEST',
                            password: 'testTEST2',
                            confirmPassword: 'testTEST2',
                            token: savedUser.resetPasswordToken.value
                        })
                        .end((err, res) => {
                            assert.equal(res.status, 400, 'should be status 400');
                            assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                            assert.equal(res.body.message, 'Token expired', 'should be \'Token expired\' message');

                            Recruiter.findOneAndUpdate({email: 'arthur@mailinator.com'},
                                {
                                    resetPasswordToken: {
                                        value: savedUser.resetPasswordToken.value,
                                        exp: savedUser.resetPasswordToken.exp
                                    }
                                }, (err, user) => {
                                    done();
                                });
                        });
                });
        });
        it('it should return okey if token is okey', (done) => {
            chai.request(server)
                .post('/auth/recruiter/reset-token')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
                    oldPassword: 'testTEST',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2',
                    token: savedUser.resetPasswordToken.value
                })
                .end((err, res) => {
                    assert.equal(res.status, 200, 'should be status 200');
                    assert.equal(res.body.message, 'Password has been changed', 'should be \'Password has been changed\' message');

                    assert.exists(res.body.accessToken, 'should have the accessToken field');
                    assert.isString(res.body.accessToken, 'accessToken should be a string');
                    assert.isAtLeast(res.body.accessToken.length, 300, 'accessToken should be at least 300 long string');

                    assert.exists(res.body.xsrfToken, 'should have the xsrfToken field');
                    assert.isString(res.body.xsrfToken, 'xsrfToken should be a string');
                    Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: any) => {
                            assert.notExists(user.resetPasswordToken, 'should delete emailVerifyToken field');
                            assert.notEqual(savedUser.hash, user.hash, 'should another password hash');
                            assert.notEqual(savedUser.salt, user.salt, 'should another password salt');
                            setTimeout(() => {
                                redisConnection.client.get('LOGOUT-TOKEN:' + authObject.recruiter.accessToken, (err: any, reply: string) => {
                                    assert.notExists(err, 'redis work');
                                    assert.exists(reply, 'token stored as logout in redis database');
                                    assert.isEmpty(reply, 'token stored without any information');

                                    authObject.recruiter.accessToken = res.body.accessToken;
                                    authObject.recruiter.xsrfToken = res.body.xsrfToken;
                                    done();
                                });
                            }, 100);
                        });
                });
        });
        it('it should return error always if user somehow can access to this route without using previously /reset/email', (done) => {
            chai.request(server)
                .post('/auth/recruiter/reset-token')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
                    oldPassword: 'testTEST',
                    password: 'testTEST2',
                    confirmPassword: 'testTEST2',
                    token: 'fakeFake'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                    assert.equal(res.body.message, 'Token wasn\'t send', 'should be \'Token wasn\'t send\' message');

                    Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: IUserDocument) => {
                            assert.notExists(user.resetPasswordToken, 'should delete resetPasswordToken field');
                            done();
                        });
                });
        });
    });
});
