import express = require('express');
import Boom = require('boom');
import Joi = require('joi');
import { BaseController } from '../base.controller';
import { IUserDocument } from '../../models/user.model';
import { IRequestWithUserId } from '../request.interface';
import { Developer } from '../../models/developer.model';
import { Recruiter } from '../../models/recruiter.model';
import { emailConfirmTokenLength } from '../../helpers/constants';

abstract class VerifyEmailController extends BaseController {
    protected readonly req: IRequestWithUserId;

    protected readonly schema = Joi.object().keys({
        token: Joi.string().length(emailConfirmTokenLength)
    }).requiredKeys(['token']);

    protected async checkToken(user: IUserDocument) {
        const token = this.req.body.token;
        if (!user) {
            throw Boom.unauthorized('User not found');
        }
        if (user.emailConfirmed) {
            return;
        }
        if (user.isEmailVerifyTokenExpired()) {
            throw Boom.badRequest('Token expired');
        }
        if (!user.isEmailVerifyTokenEqual(token)) {
            throw Boom.badRequest('Token is wrong');
        }
        user.setEmailConfirmed();
        await user.save();
    }

    protected response() {
        this.res.status(200).send({message: 'Email is confirmed'});
    }
}

class DeveloperVerifyEmailController extends VerifyEmailController {
    public handler() {
        const result = this.validate(this.req.body);
        if (result) {
            this.errorHandler(result);
            return;
        }

        Developer.findById(this.req.userId).exec()
            .then(this.checkToken.bind(this))
            .then(this.response.bind(this))
            .catch(this.errorHandler.bind(this));
    }
}

class RecruiterVerifyEmailController extends VerifyEmailController {
    public handler() {
        const result = this.validate(this.req.body);
        if (result) {
            this.errorHandler(result);
            return;
        }

        Recruiter.findById(this.req.userId).exec()
            .then(this.checkToken.bind(this))
            .then(this.response.bind(this))
            .catch(this.errorHandler.bind(this));
    }
}

/**
 * @swagger
 * definitions:
 *   VerifyEmail:
 *     type: 'object'
 *     properties:
 *       token:
 *         type: 'string'
 *     required:
 *     - token
 */

/**
 * @swagger
 * definitions:
 *   VerifyEmailResponse:
 *     type: 'object'
 *     properties:
 *       message:
 *         type: 'string'
 *     required:
 *     - message
 */

/**
 * @swagger
 * /auth/developer/verify-email:
 *   post:
 *     summary: 'Verify user email'
 *     description: ''
 *     tags: [Auth, Developer]
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     parameters:
 *       - in: 'body'
 *         name: 'body'
 *         description: ''
 *         required: true
 *         schema:
 *           $ref: '#/definitions/VerifyEmail'
 *     responses:
 *       200:
 *         description: 'Verify email successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/VerifyEmailResponse'
 *     security:
 *       - Authorization: []
 */
export function developerVerifyEmailHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const developerVerifyEmailController = new DeveloperVerifyEmailController(req, res, next);
    developerVerifyEmailController.handler();
}

/**
 * @swagger
 * /auth/recruiter/verify-email:
 *   post:
 *     summary: 'Verify user email'
 *     description: ''
 *     tags: [Auth, Recruiter]
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     parameters:
 *       - in: 'body'
 *         name: 'body'
 *         description: ''
 *         required: true
 *         schema:
 *           $ref: '#/definitions/VerifyEmail'
 *     responses:
 *       200:
 *         description: 'Verify email successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/VerifyEmailResponse'
 *     security:
 *       - Authorization: []
 */
export function recruiterVerifyEmailHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const recruiterVerifyEmailController = new RecruiterVerifyEmailController(req, res, next);
    recruiterVerifyEmailController.handler();
}
