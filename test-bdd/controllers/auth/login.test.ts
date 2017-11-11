import chai = require('chai');
import chaiHttp = require('chai-http');
import { assert } from 'chai';
import { authObject, server } from '../../helpers/constants';
import { Developer } from '../../../src/models/developer.model';
import { Recruiter } from '../../../src/models/recruiter.model';

chai.use(chaiHttp);

describe('Login for developers', () => {
    describe('/auth/developer/login', () => {
        it('it should return validation error on wrong email', (done) => {
            chai.request(server)
                .post('/auth/developer/login')
                .send({
                    email: 'arthur-mailinator.com',
                    password: 'testTEST'
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
                .post('/auth/developer/login')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'test'
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
                .post('/auth/developer/login')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'password', 'should be invalid password error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return accessToken if user is okey', (done) => {
            chai.request(server)
                .post('/auth/developer/login')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST'
                })
                .end((err, res) => {
                    assert.equal(res.status, 200, 'should be status 200');
                    assert.equal(res.body.message, 'User is authorized', 'should be \'User is authorized\' message');

                    assert.exists(res.body.accessToken, 'should have the accessToken field');
                    assert.isString(res.body.accessToken, 'accessToken should be a string');
                    assert.isAtLeast(res.body.accessToken.length, 300, 'accessToken should be at least 300 long string');

                    assert.exists(res.body.xsrfToken, 'should have the xsrfToken field');
                    assert.isString(res.body.xsrfToken, 'xsrfToken should be a string');
                    Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user) => {
                            assert.exists(user, 'user should exist');
                            authObject.developer.accessToken = res.body.accessToken;
                            authObject.developer.xsrfToken = res.body.xsrfToken;
                            done();
                        });
                });
        });
        it('it should return message if email not found', (done) => {
            chai.request(server)
                .post('/auth/developer/login')
                .send({
                    email: 'arthur-fake@mailinator.com',
                    password: 'testTEST'
                })
                .end((err, res) => {
                    assert.equal(res.status, 401, 'should be status 401');
                    assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                    assert.equal(res.body.message, 'Email not found', 'should be \'Email not found\' message');
                    done();
                });
        });
        it('it should return message if email found but password is wrong', (done) => {
            chai.request(server)
                .post('/auth/developer/login')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTESTfake'
                })
                .end((err, res) => {
                    assert.equal(res.status, 401, 'should be status 401');
                    assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                    assert.equal(res.body.message, 'Incorrect password', 'should be \'Incorrect password\' message');
                    done();
                });
        });
    });
});

describe('Login for recruiters', () => {
    describe('/auth/recruiter/login', () => {
        it('it should return validation error on wrong email', (done) => {
            chai.request(server)
                .post('/auth/recruiter/login')
                .send({
                    email: 'arthur-mailinator.com',
                    password: 'testTEST'
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
                .post('/auth/recruiter/login')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'test'
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
                .post('/auth/recruiter/login')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'password', 'should be invalid password error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    done();
                });
        });
        it('it should return accessToken if user is okey', (done) => {
            chai.request(server)
                .post('/auth/recruiter/login')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST'
                })
                .end((err, res) => {
                    assert.equal(res.status, 200, 'should be status 200');
                    assert.equal(res.body.message, 'User is authorized', 'should be \'User is authorized\' message');

                    assert.exists(res.body.accessToken, 'should have the accessToken field');
                    assert.isString(res.body.accessToken, 'accessToken should be a string');
                    assert.isAtLeast(res.body.accessToken.length, 300, 'accessToken should be at least 300 long string');

                    assert.exists(res.body.xsrfToken, 'should have the xsrfToken field');
                    assert.isString(res.body.xsrfToken, 'xsrfToken should be a string');
                    Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user) => {
                            assert.exists(user, 'user should exist');
                            authObject.recruiter.accessToken = res.body.accessToken;
                            authObject.recruiter.xsrfToken = res.body.xsrfToken;
                            done();
                        });
                });
        });
        it('it should return message if email not found', (done) => {
            chai.request(server)
                .post('/auth/recruiter/login')
                .send({
                    email: 'arthur-fake@mailinator.com',
                    password: 'testTEST'
                })
                .end((err, res) => {
                    assert.equal(res.status, 401, 'should be status 401');
                    assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                    assert.equal(res.body.message, 'Email not found', 'should be \'Email not found\' message');
                    done();
                });
        });
        it('it should return message if email found but password is wrong', (done) => {
            chai.request(server)
                .post('/auth/recruiter/login')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTESTfake'
                })
                .end((err, res) => {
                    assert.equal(res.status, 401, 'should be status 401');
                    assert.equal(res.body.error, 'Unauthorized', 'should be unauthorized error');
                    assert.equal(res.body.message, 'Incorrect password', 'should be \'Incorrect password\' message');
                    done();
                });
        });
    });
});
