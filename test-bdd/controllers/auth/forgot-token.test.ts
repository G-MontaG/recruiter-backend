import chai = require('chai');
import chaiHttp = require('chai-http');
import { assert } from 'chai';
import moment = require('moment');
import { authObject, server } from '../../helpers/constants';
import { Developer } from '../../../src/models/developer.model';
import { IUserDocument } from '../../../src/models/user.model';
import { Recruiter } from '../../../src/models/recruiter.model';

chai.use(chaiHttp);

describe('Forgot password, check token from email, for developers', () => {
    let savedUser: IUserDocument;

    before((done) => {
        Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
            .then((user: IUserDocument) => {
                savedUser = user;
                done();
            });
    });

    describe('/auth/developer/forgot-token', () => {
        it('it should return validation error on wrong email', (done) => {
            chai.request(server)
                .post('/auth/developer/forgot-token')
                .send({
                    email: 'arthur-mailinator.com',
                    token: savedUser.forgotPasswordToken.value,
                    password: 'testTEST',
                    confirmPassword: 'testTEST'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'email', 'should be invalid email error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return validation error on to short password', (done) => {
            chai.request(server)
                .post('/auth/developer/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    token: savedUser.forgotPasswordToken.value,
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
                .post('/auth/developer/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    token: savedUser.forgotPasswordToken.value,
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
                .post('/auth/developer/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    token: savedUser.forgotPasswordToken.value,
                    password: 'testTEST',
                    confirmPassword: 'testTESTfake'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'confirmPassword', 'should be invalid confirmPassword error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return validation error on to long token', (done) => {
            chai.request(server)
                .post('/auth/developer/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST',
                    confirmPassword: 'testTEST',
                    token: `${savedUser.forgotPasswordToken.value}fake`
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
                .post('/auth/developer/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST',
                    confirmPassword: 'testTEST',
                    token: savedUser.forgotPasswordToken.value.slice(0, 6)
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
                .post('/auth/developer/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST',
                    confirmPassword: 'testTEST',
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
                    forgotPasswordToken: {
                        value: savedUser.forgotPasswordToken.value,
                        exp: moment('01/01/1992', 'MM/DD/YYYY').toDate()
                    }
                }, (err, user) => {
                    chai.request(server)
                        .post('/auth/developer/forgot-token')
                        .send({
                            email: 'arthur@mailinator.com',
                            password: 'testTEST',
                            confirmPassword: 'testTEST',
                            token: savedUser.forgotPasswordToken.value
                        })
                        .end((err, res) => {
                            assert.equal(res.status, 400, 'should be status 400');
                            assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                            assert.equal(res.body.message, 'Token expired', 'should be \'Token expired\' message');

                            Developer.findOneAndUpdate({email: 'arthur@mailinator.com'},
                                {
                                    forgotPasswordToken: {
                                        value: savedUser.forgotPasswordToken.value,
                                        exp: savedUser.forgotPasswordToken.exp
                                    }
                                }, (err, user) => {
                                    done();
                                });
                        });
                });
        });
        it('it should return okey if token is okey', (done) => {
            chai.request(server)
                .post('/auth/developer/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST',
                    confirmPassword: 'testTEST',
                    token: savedUser.forgotPasswordToken.value
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
                            assert.notExists(user.forgotPasswordToken, 'should delete emailVerifyToken field');
                            assert.notEqual(savedUser.hash, user.hash, 'should another password hash');
                            assert.notEqual(savedUser.salt, user.salt, 'should another password salt');
                            done();
                        });
                });
        });
        it('it should return error always if user somehow can access to this route without using previously /forgot/email', (done) => {
            chai.request(server)
                .post('/auth/developer/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST',
                    confirmPassword: 'testTEST',
                    token: 'fakeFake'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                    assert.equal(res.body.message, 'Token wasn\'t send', 'should be \'Token wasn\'t send\' message');

                    Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: IUserDocument) => {
                            assert.notExists(user.forgotPasswordToken, 'should delete forgotPasswordToken field');
                            done();
                        });
                });
        });
    });
});

describe('Forgot password, check token from email, for recruiters', () => {
    let savedUser: IUserDocument;

    before((done) => {
        Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
            .then((user: IUserDocument) => {
                savedUser = user;
                done();
            });
    });

    describe('/auth/recruiter/forgot-token', () => {
        it('it should return validation error on wrong email', (done) => {
            chai.request(server)
                .post('/auth/recruiter/forgot-token')
                .send({
                    email: 'arthur-mailinator.com',
                    token: savedUser.forgotPasswordToken.value,
                    password: 'testTEST',
                    confirmPassword: 'testTEST'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'email', 'should be invalid email error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return validation error on to short password', (done) => {
            chai.request(server)
                .post('/auth/recruiter/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    token: savedUser.forgotPasswordToken.value,
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
                .post('/auth/recruiter/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    token: savedUser.forgotPasswordToken.value,
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
                .post('/auth/recruiter/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    token: savedUser.forgotPasswordToken.value,
                    password: 'testTEST',
                    confirmPassword: 'testTESTfake'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'confirmPassword', 'should be invalid confirmPassword error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return validation error on to long token', (done) => {
            chai.request(server)
                .post('/auth/recruiter/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST',
                    confirmPassword: 'testTEST',
                    token: `${savedUser.forgotPasswordToken.value}fake`
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
                .post('/auth/recruiter/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST',
                    confirmPassword: 'testTEST',
                    token: savedUser.forgotPasswordToken.value.slice(0, 6)
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
                .post('/auth/recruiter/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST',
                    confirmPassword: 'testTEST',
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
                    forgotPasswordToken: {
                        value: savedUser.forgotPasswordToken.value,
                        exp: moment('01/01/1992', 'MM/DD/YYYY').toDate()
                    }
                }, (err, user) => {
                    chai.request(server)
                        .post('/auth/recruiter/forgot-token')
                        .set('Authorization', `Bearer ${authObject.developer}`)
                        .send({
                            email: 'arthur@mailinator.com',
                            password: 'testTEST',
                            confirmPassword: 'testTEST',
                            token: savedUser.forgotPasswordToken.value
                        })
                        .end((err, res) => {
                            assert.equal(res.status, 400, 'should be status 400');
                            assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                            assert.equal(res.body.message, 'Token expired', 'should be \'Token expired\' message');

                            Recruiter.findOneAndUpdate({email: 'arthur@mailinator.com'},
                                {
                                    forgotPasswordToken: {
                                        value: savedUser.forgotPasswordToken.value,
                                        exp: savedUser.forgotPasswordToken.exp
                                    }
                                }, (err, user) => {
                                    done();
                                });
                        });
                });
        });
        it('it should return okey if token is okey', (done) => {
            chai.request(server)
                .post('/auth/recruiter/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST',
                    confirmPassword: 'testTEST',
                    token: savedUser.forgotPasswordToken.value
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
                            assert.notExists(user.forgotPasswordToken, 'should delete emailVerifyToken field');
                            assert.notEqual(savedUser.hash, user.hash, 'should another password hash');
                            assert.notEqual(savedUser.salt, user.salt, 'should another password salt');
                            done();
                        });
                });
        });
        it('it should return error always if user somehow can access to this route without using previously /forgot/email', (done) => {
            chai.request(server)
                .post('/auth/recruiter/forgot-token')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST',
                    confirmPassword: 'testTEST',
                    token: 'fakeFake'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                    assert.equal(res.body.message, 'Token wasn\'t send', 'should be \'Token wasn\'t send\' message');

                    Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: IUserDocument) => {
                            assert.notExists(user.forgotPasswordToken, 'should delete forgotPasswordToken field');
                            done();
                        });
                });
        });
    });
});
