import chai = require('chai');
import chaiHttp = require('chai-http');
import { assert } from 'chai';
import { server } from '../../helpers/constants';
import { Developer } from '../../../src/models/developer.model';
import { Recruiter } from '../../../src/models/recruiter.model';

chai.use(chaiHttp);

describe('Sign-up for developers', () => {
    before((done) => {
        Developer.remove({email: 'arthur@mailinator.com'}, (err) => {
            done();
        });
    });

    describe('/auth/developer/sign-up', () => {
        it('it should return validation error on wrong email', (done) => {
            chai.request(server)
                .post('/auth/developer/sign-up')
                .send({
                    email: 'arthur-mailinator.com',
                    password: 'testTEST'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'email', 'should be invalid email error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    Developer.findOne({email: 'arthur-mailinator.com'}).lean().exec()
                        .then((user) => {
                            assert.notExists(user, 'should not create user');
                            done();
                        });
                });
        });
        it('it should return validation error on to short password', (done) => {
            chai.request(server)
                .post('/auth/developer/sign-up')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'test'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'password', 'should be invalid password error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user) => {
                            assert.notExists(user, 'should not create user');
                            done();
                        });
                });
        });
        it('it should return validation error on to long password', (done) => {
            chai.request(server)
                .post('/auth/developer/sign-up')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'password', 'should be invalid password error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    Developer.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user) => {
                            assert.notExists(user, 'should not create user');
                            done();
                        });
                });
        });
        it('it should return accessToken if user is okey', (done) => {
            chai.request(server)
                .post('/auth/developer/sign-up')
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
                            assert.exists(user, 'should create user');
                            done();
                        });
                });
        });
        it('it should return message that user already exist if email used', (done) => {
            chai.request(server)
                .post('/auth/developer/sign-up')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST'
                })
                .end((err, res) => {
                    assert.equal(res.status, 409, 'should be status 409');
                    assert.equal(res.body.error, 'Conflict', 'should be conflict error');
                    assert.equal(res.body.message, 'Email is already in use', 'should be \'Email is already in use\' message');
                    done();
                });
        });
    });
});

describe('Sign-up for recruiters', () => {
    before((done) => {
        Recruiter.remove({email: 'arthur@mailinator.com'}, (err) => {
            done();
        });
    });

    describe('/auth/recruiter/sign-up', () => {
        it('it should return validation error on wrong email', (done) => {
            chai.request(server)
                .post('/auth/recruiter/sign-up')
                .send({
                    email: 'arthur-mailinator.com',
                    password: 'testTEST'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'email', 'should be invalid email error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    Recruiter.findOne({email: 'arthur-mailinator.com'}).lean().exec()
                        .then((user) => {
                            assert.notExists(user, 'should not create user');
                            done();
                        });
                });
        });
        it('it should return validation error on to short password', (done) => {
            chai.request(server)
                .post('/auth/recruiter/sign-up')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'test'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'password', 'should be invalid password error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user) => {
                            assert.notExists(user, 'should not create user');
                            done();
                        });
                });
        });
        it('it should return validation error on to long password', (done) => {
            chai.request(server)
                .post('/auth/recruiter/sign-up')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest'
                })
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error[0].path, 'password', 'should be invalid password error');
                    assert.equal(res.body.message, 'ValidationError', 'should be \'ValidationError\' message');
                    Recruiter.findOne({email: 'arthur@mailinator.com'}).lean().exec()
                        .then((user) => {
                            assert.notExists(user, 'should not create user');
                            done();
                        });
                });
        });
        it('it should return accessToken if user is okey', (done) => {
            chai.request(server)
                .post('/auth/recruiter/sign-up')
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
                            assert.exists(user, 'should create user');
                            done();
                        });
                });
        });
        it('it should return message that user already exist if email used', (done) => {
            chai.request(server)
                .post('/auth/recruiter/sign-up')
                .send({
                    email: 'arthur@mailinator.com',
                    password: 'testTEST'
                })
                .end((err, res) => {
                    assert.equal(res.status, 409, 'should be status 409');
                    assert.equal(res.body.error, 'Conflict', 'should be conflict error');
                    assert.equal(res.body.message, 'Email is already in use', 'should be \'Email is already in use\' message');
                    done();
                });
        });
    });
});
