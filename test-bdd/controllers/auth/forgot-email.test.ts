import chai = require('chai');
import chaiHttp = require('chai-http');
import moment = require('moment');
import { assert } from 'chai';
import { server } from '../../helpers/constants';
import { Developer } from '../../../src/models/developer.model';
import { IUserDocument } from '../../../src/models/user.model';
import { Recruiter } from '../../../src/models/recruiter.model';

chai.use(chaiHttp);

describe('Forgot password, send token on email, for developers', () => {
    let savedUser: IUserDocument;

    before((done) => {
        Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
            .then((user: IUserDocument) => {
                savedUser = user;
                done();
            });
    });

    describe('/auth/developer/forgot-email', () => {
        it('it should return validation error on wrong email', (done) => {
            chai.request(server)
                .post('/auth/developer/forgot-email')
                .send({
                    email: 'arthur-mailinator.com'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'email', 'should be invalid email error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return error on normal email but not belonging to the user', (done) => {
            chai.request(server)
                .post('/auth/developer/forgot-email')
                .send({
                    email: 'arthur-fake@mailinator.com'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                    assert.equal(res.body.message, 'Email not found', 'should be \'Email not found\' message');
                    done();
                });
        });
        it('it should return okey if email is okey', (done) => {
            chai.request(server)
                .post('/auth/developer/forgot-email')
                .send({
                    email: savedUser.email
                })
                .end((err, res) => {
                    assert.equal(res.status, 200, 'should be status 200');
                    assert.equal(res.body.message, 'Token has been sent', 'should be \'Token has been sent\' message');
                    Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: IUserDocument) => {
                            assert.exists(user.forgotPasswordToken, 'forgotPasswordToken should exist');
                            assert.isString(user.forgotPasswordToken.value, 'forgotPasswordToken should exist');
                            assert.exists(user.forgotPasswordToken.exp, 'forgotPasswordToken should exist');
                            assert.isTrue(moment(user.forgotPasswordToken.exp) > moment(), 'expire time should be greater then now');
                            savedUser = user;
                            done();
                        });
                });
        });
        it('it should return message token already send if it was send and not expired', (done) => {
            chai.request(server)
                .post('/auth/developer/forgot-email')
                .send({
                    email: savedUser.email
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                    assert.equal(res.body.message, 'Email was send', 'should be \'Email was send\' message');
                    Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: IUserDocument) => {
                            assert.exists(user.forgotPasswordToken, 'forgotPasswordToken should exist');
                            assert.isTrue(moment(user.forgotPasswordToken.exp) > moment(), 'expire time should be greater then now');
                            done();
                        });
                });
        });
        it('it should return message new token send if it was send previously but expired', (done) => {
            Developer.findOneAndUpdate({email: 'arthur@mailinator.com'},
                {
                    forgotPasswordToken: {
                        value: savedUser.forgotPasswordToken.value,
                        exp: moment('01/01/1992', 'MM/DD/YYYY').toDate()
                    }
                }, (err, user) => {
                    chai.request(server)
                        .post('/auth/developer/forgot-email')
                        .send({
                            email: savedUser.email
                        })
                        .end((err, res) => {
                            assert.equal(res.status, 200, 'should be status 200');
                            assert.equal(res.body.message, 'Token has been sent', 'should be \'Token has been sent\' message');

                            Developer.findOneAndUpdate({email: 'arthur@mailinator.com'},
                                {
                                    forgotPasswordToken: {
                                        value: savedUser.forgotPasswordToken.value,
                                        exp: savedUser.forgotPasswordToken.exp
                                    }
                                },
                                {new: true},
                                (err, user) => {
                                    assert.exists(user.forgotPasswordToken, 'forgotPasswordToken should exist');
                                    assert.isTrue(moment(user.forgotPasswordToken.exp) > moment(), 'expire time should be greater then now');
                                    done();
                                });
                        });
                });
        });
    });
});

describe('Forgot password, send token on email, for recruiters', () => {
    let savedUser: IUserDocument;

    before((done) => {
        Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
            .then((user: IUserDocument) => {
                savedUser = user;
                done();
            });
    });

    describe('/auth/recruiters/forgot-email', () => {
        it('it should return validation error on wrong email', (done) => {
            chai.request(server)
                .post('/auth/recruiter/forgot-email')
                .send({
                    email: 'arthur-mailinator.com'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'email', 'should be invalid email error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return error on normal email but not belonging to the user', (done) => {
            chai.request(server)
                .post('/auth/recruiter/forgot-email')
                .send({
                    email: 'arthur-fake@mailinator.com'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                    assert.equal(res.body.message, 'Email not found', 'should be \'Email not found\' message');
                    done();
                });
        });
        it('it should return okey if email is okey', (done) => {
            chai.request(server)
                .post('/auth/recruiter/forgot-email')
                .send({
                    email: savedUser.email
                })
                .end((err, res) => {
                    assert.equal(res.status, 200, 'should be status 200');
                    assert.equal(res.body.message, 'Token has been sent', 'should be \'Token has been sent\' message');
                    Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: IUserDocument) => {
                            assert.exists(user.forgotPasswordToken, 'forgotPasswordToken should exist');
                            assert.isString(user.forgotPasswordToken.value, 'forgotPasswordToken should exist');
                            assert.exists(user.forgotPasswordToken.exp, 'forgotPasswordToken should exist');
                            assert.isTrue(moment(user.forgotPasswordToken.exp) > moment(), 'expire time should be greater then now');
                            savedUser = user;
                            done();
                        });
                });
        });
        it('it should return message token already send if it was send and not expired', (done) => {
            chai.request(server)
                .post('/auth/recruiter/forgot-email')
                .send({
                    email: savedUser.email
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                    assert.equal(res.body.message, 'Email was send', 'should be \'Email was send\' message');
                    Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: IUserDocument) => {
                            assert.exists(user.forgotPasswordToken, 'forgotPasswordToken should exist');
                            assert.isTrue(moment(user.forgotPasswordToken.exp) > moment(), 'expire time should be greater then now');
                            done();
                        });
                });
        });
        it('it should return message new token send if it was send previously but expired', (done) => {
            Recruiter.findOneAndUpdate({email: 'arthur@mailinator.com'},
                {
                    forgotPasswordToken: {
                        value: savedUser.forgotPasswordToken.value,
                        exp: moment('01/01/1992', 'MM/DD/YYYY').toDate()
                    }
                }, (err, user) => {
                    chai.request(server)
                        .post('/auth/recruiter/forgot-email')
                        .send({
                            email: savedUser.email
                        })
                        .end((err, res) => {
                            assert.equal(res.status, 200, 'should be status 200');
                            assert.equal(res.body.message, 'Token has been sent', 'should be \'Token has been sent\' message');

                            Recruiter.findOneAndUpdate({email: 'arthur@mailinator.com'},
                                {
                                    forgotPasswordToken: {
                                        value: savedUser.forgotPasswordToken.value,
                                        exp: savedUser.forgotPasswordToken.exp
                                    }
                                },
                                {new: true},
                                (err, user) => {
                                    assert.exists(user.forgotPasswordToken, 'forgotPasswordToken should exist');
                                    assert.isTrue(moment(user.forgotPasswordToken.exp) > moment(), 'expire time should be greater then now');
                                    done();
                                });
                        });
                });
        });
    });
});
