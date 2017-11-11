import express = require('express');
import Boom = require('boom');
import Joi = require('joi');
import { BaseController } from '../base.controller';
import { IUserDocument } from '../../models/user.model';
import { Developer } from '../../models/developer.model';
import { Recruiter } from '../../models/recruiter.model';

abstract class ForgotEmailController extends BaseController {
    protected readonly schema = Joi.object().keys({
        email: Joi.string().email()
    }).requiredKeys(['email']);

    protected checkUserExist(user: IUserDocument) {
        if (!user) {
            throw Boom.badRequest('Email not found');
        }
        if (user.forgotPasswordToken && user.forgotPasswordToken.exp && !user.isForgotPasswordTokenExpired()) {
            throw Boom.badRequest('Email was send');
        }
        return user;
    }

    protected generateToken(user: IUserDocument) {
        user.createForgotPasswordToken();
        return user;
    }

    protected async saveUser(user: IUserDocument) {
        await user.save();
        return user;
    }

    protected sendForgotEmailVerification(user: IUserDocument) {
        const mailOptions = {
            to: user.email,
            from: 'arthur.osipenko@gmail.com',
            subject: 'Forgot password',
            text: `Hello. This is a token for your account 
                   ${user.forgotPasswordToken.value}
                   Please go back and enter it in forgot password form.`
        };
        //TODO: send email
        return user;
    }

    protected responseToken() {
        this.res.status(200).send({message: 'Token has been sent'});
    }
}

class DeveloperForgotEmailController extends ForgotEmailController {
    public handler() {
        const result = this.validate(this.req.body);
        if (result) {
            this.errorHandler(result);
            return;
        }

        Developer.findOne({email: this.req.body.email}).exec()
            .then(this.checkUserExist.bind(this))
            .then(this.generateToken.bind(this))
            .then(this.saveUser.bind(this))
            .then(this.sendForgotEmailVerification.bind(this))
            .then(this.responseToken.bind(this))
            .catch(this.errorHandler.bind(this));
    }
}

class RecruiterForgotEmailController extends ForgotEmailController {
    public handler() {
        const result = this.validate(this.req.body);
        if (result) {
            this.errorHandler(result);
            return;
        }

        Recruiter.findOne({email: this.req.body.email}).exec()
            .then(this.checkUserExist.bind(this))
            .then(this.generateToken.bind(this))
            .then(this.saveUser.bind(this))
            .then(this.sendForgotEmailVerification.bind(this))
            .then(this.responseToken.bind(this))
            .catch(this.errorHandler.bind(this));
    }
}

/**
 * @swagger
 * definitions:
 *   ForgotEmail:
 *     type: 'object'
 *     properties:
 *       email:
 *         type: 'string'
 *     required:
 *     - email
 */

/**
 * @swagger
 * definitions:
 *   ForgotEmailResponse:
 *     type: 'object'
 *     properties:
 *       message:
 *         type: 'string'
 *     required:
 *     - message
 */

/**
 * @swagger
 * /auth/developer/forgot/email:
 *   post:
 *     summary: 'Forgot password, send email token to verify user existing'
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
 *           $ref: '#/definitions/ForgotEmail'
 *     responses:
 *       200:
 *         description: 'Verify email and send token successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/ForgotEmailResponse'
 */
export function developerForgotEmailHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const developerForgotEmailController = new DeveloperForgotEmailController(req, res, next);
    developerForgotEmailController.handler();
}

/**
 * @swagger
 * /auth/recruiter/forgot/email:
 *   post:
 *     summary: 'Forgot password, send email token to verify user existing'
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
 *           $ref: '#/definitions/ForgotEmail'
 *     responses:
 *       200:
 *         description: 'Verify email and send token successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/ForgotEmailResponse'
 */
export function recruiterForgotEmailHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const recruiterForgotEmailController = new RecruiterForgotEmailController(req, res, next);
    recruiterForgotEmailController.handler();
}
