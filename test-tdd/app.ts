import chai = require('chai');
import chaiHttp = require('chai-http');
import { assert } from 'chai';
import { server } from './helpers/constants';

chai.use(chaiHttp);

suite('Array', function() {
    setup(function() {
        // ...
    });

    suite('#indexOf()', function() {
        test('should return -1 when not present', function() {
            assert.equal(-1, [1,2,3].indexOf(4));
        });
    });
});
