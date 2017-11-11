import chai = require('chai');
import chaiHttp = require('chai-http');
import { assert } from 'chai';
import moment = require('moment');
import { authObject, server } from '../../helpers/constants';
import { Developer } from '../../../src/models/developer.model';
import { IUserDocument } from '../../../src/models/user.model';
import { Recruiter } from '../../../src/models/recruiter.model';

chai.use(chaiHttp);

describe('Reset password, send token on email, for developers', () => {
    let savedUser: IUserDocument;

    before((done) => {
        Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
            .then((user: IUserDocument) => {
                savedUser = user;
                done();
            });
    });

    describe('/auth/developer/reset-email', () => {
        it('it should return unauthorized error if request without authorization token', (done) => {
            chai.request(server)
                .post('/auth/developer/reset-email')
                .end((err, res) => {
                    assert.equal(res.status, 401, 'should be status 401');
                    assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                    assert.equal(res.body.message, 'Authorization token is undefined', 'should be \'Authorization token is undefined\' message');
                    done();
                });
        });
        it('it should return okey if token send', (done) => {
            chai.request(server)
                .post('/auth/developer/reset-email')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .end((err, res) => {
                    assert.equal(res.status, 200, 'should be status 200');
                    assert.equal(res.body.message, 'Token has been sent', 'should be \'Token has been sent\' message');
                    Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: IUserDocument) => {
                            assert.exists(user.resetPasswordToken, 'resetPasswordToken should exist');
                            assert.isString(user.resetPasswordToken.value, 'resetPasswordToken should exist');
                            assert.exists(user.resetPasswordToken.exp, 'resetPasswordToken should exist');
                            assert.isTrue(moment(user.resetPasswordToken.exp) > moment(), 'expire time should be greater then now');
                            savedUser = user;
                            done();
                        });
                });
        });
        it('it should return message token already send if it was send and not expired', (done) => {
            chai.request(server)
                .post('/auth/developer/reset-email')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                    assert.equal(res.body.message, 'Email was send', 'should be \'Email was send\' message');
                    Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: IUserDocument) => {
                            assert.exists(user.resetPasswordToken, 'resetPasswordToken should exist');
                            assert.isTrue(moment(user.resetPasswordToken.exp) > moment(), 'expire time should be greater then now');
                            done();
                        });
                });
        });
        it('it should return message new token send if it was send previously but expired', (done) => {
            Developer.findOneAndUpdate({email: 'arthur@mailinator.com'},
                {
                    resetPasswordToken: {
                        value: savedUser.resetPasswordToken.value,
                        exp: moment('01/01/1992', 'MM/DD/YYYY').toDate()
                    }
                }, (err, user) => {
                    chai.request(server)
                        .post('/auth/developer/reset-email')
                        .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                        .set('X-CSRF-Token', authObject.developer.xsrfToken)
                        .end((err, res) => {
                            assert.equal(res.status, 200, 'should be status 200');
                            assert.equal(res.body.message, 'Token has been sent', 'should be \'Token has been sent\' message');

                            Developer.findOneAndUpdate({email: 'arthur@mailinator.com'},
                                {
                                    resetPasswordToken: {
                                        value: savedUser.resetPasswordToken.value,
                                        exp: savedUser.resetPasswordToken.exp
                                    }
                                },
                                {new: true},
                                (err, user) => {
                                    assert.exists(user.resetPasswordToken, 'forgotPasswordToken should exist');
                                    assert.isTrue(moment(user.resetPasswordToken.exp) > moment(), 'expire time should be greater then now');
                                    done();
                                });
                        });
                });
        });
    });
});

describe('Reset password, send token on email, for recruiters', () => {
    let savedUser: IUserDocument;

    before((done) => {
        Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
            .then((user: IUserDocument) => {
                savedUser = user;
                done();
            });
    });

    describe('/auth/recruiter/reset-email', () => {
        it('it should return unauthorized error if request without authorization token', (done) => {
            chai.request(server)
                .post('/auth/recruiter/reset-email')
                .end((err, res) => {
                    assert.equal(res.status, 401, 'should be status 401');
                    assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                    assert.equal(res.body.message, 'Authorization token is undefined', 'should be \'Authorization token is undefined\' message');
                    done();
                });
        });
        it('it should return okey if token send', (done) => {
            chai.request(server)
                .post('/auth/recruiter/reset-email')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .end((err, res) => {
                    assert.equal(res.status, 200, 'should be status 200');
                    assert.equal(res.body.message, 'Token has been sent', 'should be \'Token has been sent\' message');
                    Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: IUserDocument) => {
                            assert.exists(user.resetPasswordToken, 'resetPasswordToken should exist');
                            assert.isString(user.resetPasswordToken.value, 'resetPasswordToken should exist');
                            assert.exists(user.resetPasswordToken.exp, 'resetPasswordToken should exist');
                            assert.isTrue(moment(user.resetPasswordToken.exp) > moment(), 'expire time should be greater then now');
                            savedUser = user;
                            done();
                        });
                });
        });
        it('it should return message token already send if it was send and not expired', (done) => {
            chai.request(server)
                .post('/auth/recruiter/reset-email')
                .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error, 'Bad Request', 'should be bad request token error');
                    assert.equal(res.body.message, 'Email was send', 'should be \'Email was send\' message');
                    Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user: IUserDocument) => {
                            assert.exists(user.resetPasswordToken, 'resetPasswordToken should exist');
                            assert.isTrue(moment(user.resetPasswordToken.exp) > moment(), 'expire time should be greater then now');
                            done();
                        });
                });
        });
        it('it should return message new token send if it was send previously but expired', (done) => {
            Recruiter.findOneAndUpdate({email: 'arthur@mailinator.com'},
                {
                    resetPasswordToken: {
                        value: savedUser.resetPasswordToken.value,
                        exp: moment('01/01/1992', 'MM/DD/YYYY').toDate()
                    }
                }, (err, user) => {
                    chai.request(server)
                        .post('/auth/recruiter/reset-email')
                        .set('Authorization', `Bearer ${authObject.recruiter.accessToken}`)
                        .set('X-CSRF-Token', authObject.recruiter.xsrfToken)
                        .end((err, res) => {
                            assert.equal(res.status, 200, 'should be status 200');
                            assert.equal(res.body.message, 'Token has been sent', 'should be \'Token has been sent\' message');

                            Recruiter.findOneAndUpdate({email: 'arthur@mailinator.com'},
                                {
                                    resetPasswordToken: {
                                        value: savedUser.resetPasswordToken.value,
                                        exp: savedUser.resetPasswordToken.exp
                                    }
                                },
                                {new: true},
                                (err, user) => {
                                    assert.exists(user.resetPasswordToken, 'forgotPasswordToken should exist');
                                    assert.isTrue(moment(user.resetPasswordToken.exp) > moment(), 'expire time should be greater then now');
                                    done();
                                });
                        });
                });
        });
    });
});
