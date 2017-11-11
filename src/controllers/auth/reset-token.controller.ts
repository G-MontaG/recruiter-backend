import express = require('express');
import Boom = require('boom');
import Joi = require('joi');
import { BaseController } from '../base.controller';
import { IUserDocument } from '../../models/user.model';
import { IRequestWithUserId } from '../request.interface';
import { Developer } from '../../models/developer.model';
import { Recruiter } from '../../models/recruiter.model';
import { logoutHandler } from './logout.controller';
import { passwordMaxLength, passwordMinLength, resetPasswordTokenLength } from '../../helpers/constants';

abstract class ResetTokenController extends BaseController {
    protected readonly req: IRequestWithUserId;

    protected readonly schema = Joi.object().keys({
        token: Joi.string().length(resetPasswordTokenLength),
        oldPassword: Joi.string().regex(new RegExp(`^[a-zA-Z0-9]{${passwordMinLength},${passwordMaxLength}}$`)),
        password: Joi.string().regex(new RegExp(`^[a-zA-Z0-9]{${passwordMinLength},${passwordMaxLength}}$`)),
        confirmPassword: Joi.string().valid(Joi.ref('password'))
    }).requiredKeys(['token', 'oldPassword', 'password', 'confirmPassword']);

    protected checkToken(user: IUserDocument) {
        const token = this.req.body.token;
        if (!user) {
            throw Boom.unauthorized('User not found');
        }
        if (!user.resetPasswordToken || !user.resetPasswordToken.value) {
            throw Boom.badRequest('Token wasn\'t send');
        }
        if (user.isResetPasswordTokenExpired()) {
            throw Boom.badRequest('Token expired');
        }
        if (!user.isResetPasswordTokenEqual(token)) {
            throw Boom.badRequest('Token is wrong');
        }
        user.setResetPasswordTokenUsed();
        return user;
    }

    protected async checkPassword(user: IUserDocument) {
        const result = await user.checkPassword(this.req.body.oldPassword);
        return {user, result};
    }

    protected verifyResult(params: {user: IUserDocument, result: any}) {
        if (!params.result) {
            throw Boom.badRequest('Incorrect password');
        }
        return params.user;
    }

    protected async cryptPassword(user: IUserDocument) {
        await user.cryptPassword(this.req.body.password);
        return user;
    }

    protected async saveUser(user: IUserDocument) {
        await user.save();
        return user;
    }

    protected logoutPreviousAuthToken() {
        logoutHandler(this.req, this.res, this.next, true);
    }

    protected response(user: IUserDocument, type: string) {
        const tokenObject = this.generateAccessToken(user, type);
        this.res.status(200).send(Object.assign({},
            {message: 'Password has been changed'},
            tokenObject));
    }
}

class DeveloperResetTokenController extends ResetTokenController {
    public handler(): any {
        const result = this.validate(this.req.body);
        const resultEquality = this.validate(this.req.body, Joi.object().keys({
            token: Joi.string(),
            password: Joi.string(),
            confirmPassword: Joi.string(),
            //oldPassword: Joi.string().invalid(Joi.ref('password')),
            oldPassword: Joi.string()
        }));
        if (result || resultEquality) {
            this.errorHandler(result || resultEquality);
            return null;
        }

        Developer.findById(this.req.userId).exec()
            .then(this.checkToken.bind(this))
            .then(this.checkPassword.bind(this))
            .then(this.verifyResult.bind(this))
            .then(this.cryptPassword.bind(this))
            .then(this.saveUser.bind(this))
            .then(this.response.bind(this))
            .then(this.logoutPreviousAuthToken.bind(this))
            .catch(this.errorHandler.bind(this));
    }

    protected response(user: IUserDocument) {
        super.response(user,'developer');
    }
}

class RecruiterResetTokenController extends ResetTokenController {
    public handler(): any {
        const result = this.validate(this.req.body);
        const resultEquality = this.validate(this.req.body, Joi.object().keys({
            token: Joi.string(),
            password: Joi.string(),
            confirmPassword: Joi.string(),
            //oldPassword: Joi.string().invalid(Joi.ref('password')),
            oldPassword: Joi.string()
        }));
        if (result || resultEquality) {
            this.errorHandler(result || resultEquality);
            return null;
        }

        Recruiter.findById(this.req.userId).exec()
            .then(this.checkToken.bind(this))
            .then(this.checkPassword.bind(this))
            .then(this.verifyResult.bind(this))
            .then(this.cryptPassword.bind(this))
            .then(this.saveUser.bind(this))
            .then(this.response.bind(this))
            .then(this.logoutPreviousAuthToken.bind(this))
            .catch(this.errorHandler.bind(this));
    }

    protected response(user: IUserDocument) {
        super.response(user,'recruiter');
    }
}

/**
 * @swagger
 * definitions:
 *   ResetToken:
 *     type: 'object'
 *     properties:
 *       token:
 *         type: 'string'
 *       oldPassword:
 *         type: 'string'
 *         minLength: 8
 *         maxLength: 30
 *       password:
 *         type: 'string'
 *         minLength: 8
 *         maxLength: 30
 *       confirmPassword:
 *         type: 'string'
 *         minLength: 8
 *         maxLength: 30
 *     required:
 *     - token
 *     - oldPassword
 *     - password
 *     - confirmPassword
 */

/**
 * @swagger
 * definitions:
 *   ResetTokenResponse:
 *     type: 'object'
 *     properties:
 *       message:
 *         type: 'string'
 *       accessToken:
 *         type: 'string'
 *       xsrfToken:
 *         type: 'string'
 *     required:
 *     - message
 *     - accessToken
 *     - xsrfToken
 */

/**
 * @swagger
 * /auth/developer/reset/token:
 *   post:
 *     summary: 'Reset password, verify token from email and set new password'
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
 *           $ref: '#/definitions/ResetToken'
 *     responses:
 *       200:
 *         description: 'Verify token and set new password successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/ResetTokenResponse'
 */
export function developerResetTokenHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const developerResetTokenController = new DeveloperResetTokenController(req, res, next);
    developerResetTokenController.handler();
}

/**
 * @swagger
 * /auth/recruiter/reset/token:
 *   post:
 *     summary: 'Reset password, verify token from email and set new password'
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
 *           $ref: '#/definitions/ResetToken'
 *     responses:
 *       200:
 *         description: 'Verify token and set new password successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/ResetTokenResponse'
 */
export function recruiterResetTokenHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const recruiterResetTokenController = new RecruiterResetTokenController(req, res, next);
    recruiterResetTokenController.handler();
}
