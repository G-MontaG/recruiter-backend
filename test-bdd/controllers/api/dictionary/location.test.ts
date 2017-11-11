import chai = require('chai');
import chaiHttp = require('chai-http');
import { assert } from 'chai';
import { authObject, server } from '../../../helpers/constants';

chai.use(chaiHttp);

describe('Location dictionary for developers', () => {
    describe('/api/developer/dictionary/location', () => {
        it('it should return list of locations', (done) => {
            chai.request(server)
                .get('/api/developer/dictionary/location')
                .set('Authorization', `Bearer ${authObject.developer.accessToken}`)
                .set('X-CSRF-Token', authObject.developer.xsrfToken)
                .end((err, res) => {
                    assert.equal(res.status, 200, 'should be status 200');
                    assert.isArray(res.body,  'should be array of locations');
                    assert.isString(res.body[0]._id,  'location should have _id');
                    assert.isString(res.body[0].text,  'location should have text');
                    done();
                });
        });
    });
});
