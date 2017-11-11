import express = require('express');
import { BaseController } from '../../base.controller';
import { DictionaryLocation, ILocationDocument } from '../../../models/dictionaries/location.model';

abstract class DictionaryLocationController extends BaseController {
    protected responseToken(locations: Array<ILocationDocument>) {
        this.res.status(200).send(locations);
    }
}

class DeveloperDictionaryLocationController extends DictionaryLocationController {
    public handler() {
        DictionaryLocation.find({}).lean().exec()
            .then(this.responseToken.bind(this))
            .catch(this.errorHandler.bind(this));
    }
}

class RecruiterDictionaryLocationController extends DictionaryLocationController {
    public handler() {
        DictionaryLocation.find({}).lean().exec()
            .then(this.responseToken.bind(this))
            .catch(this.errorHandler.bind(this));
    }
}

/**
 * @swagger
 * definitions:
 *   DictionaryLocation:
 *     type: 'object'
 *     properties:
 *       value:
 *         type: 'string'
 *       label:
 *         type: 'string'
 *     required:
 *     - value
 *     - label
 */

/**
 * @swagger
 * /api/developer/dictionary/location:
 *   get:
 *     summary: 'Location dictionary'
 *     description: ''
 *     tags: [API, Developer]
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: 'Location get successful'
 *         schema:
 *           type: 'array'
 *           items:
 *              type: 'object'
 *              $ref: '#/definitions/DictionaryLocation'
 *     security:
 *       - Authorization: []
 */
export function developerDictionaryLocationHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const developerDictionaryLocationController = new DeveloperDictionaryLocationController(req, res, next);
    developerDictionaryLocationController.handler();
}

/**
 * @swagger
 * /api/recruiter/dictionary/location:
 *   get:
 *     summary: 'Location dictionary'
 *     description: ''
 *     tags: [API, Recruiter]
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: 'Location get successful'
 *         schema:
 *           type: 'array'
 *           items:
 *              type: 'object'
 *              $ref: '#/definitions/DictionaryLocation'
 *     security:
 *       - Authorization: []
 */
export function recruiterDictionaryLocationHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const recruiterDictionaryLocationController = new RecruiterDictionaryLocationController(req, res, next);
    recruiterDictionaryLocationController.handler();
}
