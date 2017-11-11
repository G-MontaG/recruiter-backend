import chai = require('chai');
import chaiHttp = require('chai-http');
import { assert } from 'chai';
import fs = require('fs');
import path = require('path');
import { authObject, server } from '../../helpers/constants';

chai.use(chaiHttp);

const normalFile = fs.readFileSync(path.resolve('./test-bdd/controllers/api/normal-img.png'));
const large = fs.readFileSync(path.resolve('./test-bdd/controllers/api/large.png'));
const wrongTypeFile = fs.readFileSync(path.resolve('./test-bdd/controllers/api/wrong-type.pdf'));

describe('Upload avatar for developers', () => {
    describe('/api/developer/avatar', () => {
        it('it should return validation error on wrong mimetype', (done) => {
            chai.request(server)
                .post('/api/developer/avatar')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .attach('avatar', wrongTypeFile, 'file')
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error, 'Bad Request', 'should be bad Request');
                    assert.equal(res.body.message, 'Wrong mimetype', 'should be \'Wrong mimetype\' message');
                    done();
                });
        });
        it('it should return validation error on size type', (done) => {
            chai.request(server)
                .post('/api/developer/avatar')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .attach('avatar', large, 'file')
                .end((err, res) => {
                    assert.equal(res.status, 413, 'should be status 413');
                    assert.isEmpty(res.body, 'should be nginx page');
                    done();
                });
        });
    });
});

describe('Upload avatar for recruiters', () => {
    describe('/api/recruiter/avatar', () => {
        it('it should return validation error on wrong mimetype', (done) => {
            chai.request(server)
                .post('/api/recruiter/avatar')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .attach('avatar', wrongTypeFile, 'file')
                .end((err, res) => {
                    assert.equal(res.status, 400, 'should be status 400');
                    assert.equal(res.body.error, 'Bad Request', 'should be bad Request');
                    assert.equal(res.body.message, 'Wrong mimetype', 'should be \'Wrong mimetype\' message');
                    done();
                });
        });
        it('it should return validation error on size type', (done) => {
            chai.request(server)
                .post('/api/recruiter/avatar')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .attach('avatar', large, 'file')
                .end((err, res) => {
                    assert.equal(res.status, 413, 'should be status 413');
                    assert.isEmpty(res.body, 'should be nginx page');
                    done();
                });
        });
    });
});
