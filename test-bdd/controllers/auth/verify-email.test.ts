import chai = require('chai');
import chaiHttp = require('chai-http');
import { assert } from 'chai';
import moment = require('moment');
import { authObject, server } from '../../helpers/constants';
import { Developer } from '../../../src/models/developer.model';
import { IUserDocument } from '../../../src/models/user.model';
import { Recruiter } from '../../../src/models/recruiter.model';

chai.use(chaiHttp);

describe('Verify email for developers', () => {
    let savedUser: IUserDocument;

    before((done) => {
        Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
            .then((user: IUserDocument) => {
                savedUser = user;
                done();
            });
    });

    describe('/auth/developer/verify-email', () => {
        it('it should return unauthorized error if request without authorization token', (done) => {
            chai.request(server)
                .post('/auth/developer/verify-email')
                .send({
                    token: savedUser.emailVerifyToken.value
                })
                .end((err, res) => {
                    assert.equal(res.status, 401, 'should be status 401');
                    assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                    assert.equal(res.body.message, 'Authorization token is undefined', 'should be \'Authorization token is undefined\' message');
                    done();
                });
        });
        it('it should return validation error on to long token', (done) => {
            chai.request(server)
                .post('/auth/developer/verify-email')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
                    token: `${savedUser.emailVerifyToken.value}fake`
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
                .post('/auth/developer/verify-email')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
                    token: savedUser.emailVerifyToken.value.slice(0, 6)
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
                .post('/auth/developer/verify-email')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
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
                    emailVerifyToken: {
                        value: savedUser.emailVerifyToken.value,
                        exp: moment('01/01/1992', 'MM/DD/YYYY').toDate()
                    }
                }, (err, user) => {
                    chai.request(server)
                        .post('/auth/developer/verify-email')
                        .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                        .set('X-CSRF-Token', authObject.developer.xsrfToken)
                        .send({
                            token: savedUser.emailVerifyToken.value
                        })
                        .end((err, res) => {
                            assert.equal(res.status, 400, 'should be status 400');
                            assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                            assert.equal(res.body.message, 'Token expired', 'should be \'Token expired\' message');

                            Developer.findOneAndUpdate({email: 'arthur@mailinator.com'},
                                {
                                    emailVerifyToken: {
                                        value: savedUser.emailVerifyToken.value,
                                        exp: savedUser.emailVerifyToken.exp
                                    }
                                }, (err, user) => {
                                    done();
                                });
                        });
                });
        });
        it('it should return okey if token is okey', (done) => {
            chai.request(server)
                .post('/auth/developer/verify-email')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
                    token: savedUser.emailVerifyToken.value
                })
                .end((err, res) => {
                    assert.equal(res.status, 200, 'should be status 200');
                    assert.equal(res.body.message, 'Email is confirmed', 'should be \'Email is confirmed\' message');

                    Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: any) => {
                            assert.notExists(user.emailVerifyToken, 'should delete emailVerifyToken field');
                            assert.isTrue(user.emailConfirmed, 'should have truly emailConfirmed field');
                            done();
                        });
                });
        });
        it('it should return okey always, no matter witch token you use, if email already confirmed', (done) => {
            chai.request(server)
                .post('/auth/developer/verify-email')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .send({
                    token: 'fakeFake'
                })
                .end((err, res) => {
                    assert.equal(res.status, 200, 'should be status 200');
                    assert.equal(res.body.message, 'Email is confirmed', 'should be \'Email is confirmed\' message');

                    Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: any) => {
                            assert.notExists(user.emailVerifyToken, 'should delete emailVerifyToken field');
                            assert.isTrue(user.emailConfirmed, 'should have truly emailConfirmed field');
                            done();
                        });
                });
        });
    });
});

describe('Verify email for recruiters', () => {
    let savedUser: IUserDocument;

    before((done) => {
        Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
            .then((user: IUserDocument) => {
                savedUser = user;
                done();
            });
    });

    describe('/auth/recruiter/verify-email', () => {
        it('it should return unauthorized error if request without authorization token', (done) => {
            chai.request(server)
                .post('/auth/recruiter/verify-email')
                .send({
                    token: savedUser.emailVerifyToken.value
                })
                .end((err, res) => {
                    assert.equal(res.status, 401, 'should be status 401');
                    assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                    assert.equal(res.body.message, 'Authorization token is undefined', 'should be \'Authorization token is undefined\' message');
                    done();
                });
        });
        it('it should return validation error on to long token', (done) => {
            chai.request(server)
                .post('/auth/recruiter/verify-email')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
                    token: `${savedUser.emailVerifyToken.value}fake`
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
                .post('/auth/recruiter/verify-email')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
                    token: savedUser.emailVerifyToken.value.slice(0, 6)
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
                .post('/auth/recruiter/verify-email')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
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
                    emailVerifyToken: {
                        value: savedUser.emailVerifyToken.value,
                        exp: moment('01/01/1992', 'MM/DD/YYYY').toDate()
                    }
                }, (err, user) => {
                    chai.request(server)
                        .post('/auth/recruiter/verify-email')
                        .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                        .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                        .send({
                            token: savedUser.emailVerifyToken.value
                        })
                        .end((err, res) => {
                            assert.equal(res.status, 400, 'should be status 400');
                            assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                            assert.equal(res.body.message, 'Token expired', 'should be \'Token expired\' message');

                            Recruiter.findOneAndUpdate({email: 'arthur@mailinator.com'},
                                {
                                    emailVerifyToken: {
                                        value: savedUser.emailVerifyToken.value,
                                        exp: savedUser.emailVerifyToken.exp
                                    }
                                }, (err, user) => {
                                    done();
                                });
                        });
                });
        });
        it('it should return okey if token is okey', (done) => {
            chai.request(server)
                .post('/auth/recruiter/verify-email')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
                    token: savedUser.emailVerifyToken.value
                })
                .end((err, res) => {
                    assert.equal(res.status, 200, 'should be status 200');
                    assert.equal(res.body.message, 'Email is confirmed', 'should be \'Email is confirmed\' message');

                    Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: any) => {
                            assert.notExists(user.emailVerifyToken, 'should delete emailVerifyToken field');
                            assert.isTrue(user.emailConfirmed, 'should have truly emailConfirmed field');
                            done();
                        });
                });
        });
        it('it should return okey always, no matter witch token you use, if email already confirmed', (done) => {
            chai.request(server)
                .post('/auth/recruiter/verify-email')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .send({
                    token: 'fakeFake'
                })
                .end((err, res) => {
                    assert.equal(res.status, 200, 'should be status 200');
                    assert.equal(res.body.message, 'Email is confirmed', 'should be \'Email is confirmed\' message');

                    Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: any) => {
                            assert.notExists(user.emailVerifyToken, 'should delete emailVerifyToken field');
                            assert.isTrue(user.emailConfirmed, 'should have truly emailConfirmed field');
                            done();
                        });
                });
        });
    });
});
