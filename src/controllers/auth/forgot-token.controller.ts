import express = require('express');
import Boom = require('boom');
import Joi = require('joi');
import { BaseController } from '../base.controller';
import { IUserDocument } from '../../models/user.model';
import { Developer } from '../../models/developer.model';
import { Recruiter } from '../../models/recruiter.model';
import { forgotPasswordTokenLength, passwordMaxLength, passwordMinLength } from '../../helpers/constants';

abstract class ForgotTokenController extends BaseController {
    protected readonly schema = Joi.object().keys({
        email: Joi.string().email(),
        token: Joi.string().length(forgotPasswordTokenLength),
        password: Joi.string().regex(new RegExp(`^[a-zA-Z0-9]{${passwordMinLength},${passwordMaxLength}}$`)),
        confirmPassword: Joi.string().valid(Joi.ref('password'))
    }).requiredKeys(['email', 'token', 'password', 'confirmPassword']);

    protected checkToken(user: IUserDocument) {
        const token = this.req.body.token;
        if (!user) {
            throw Boom.unauthorized('User not found');
        }
        if (!user.forgotPasswordToken || !user.forgotPasswordToken.value) {
            throw Boom.badRequest('Token wasn\'t send');
        }
        if (user.isForgotPasswordTokenExpired()) {
            throw Boom.badRequest('Token expired');
        }
        if (!user.isForgotPasswordTokenEqual(token)) {
            throw Boom.badRequest('Token is wrong');
        }
        user.setForgotPasswordTokenUsed();
        return user;
    }

    protected async cryptPassword(user: IUserDocument) {
        await user.cryptPassword(this.req.body.password);
        return user;
    }

    protected async saveUser(user: IUserDocument) {
        await user.save();
        return user;
    }

    protected response(user: IUserDocument, type: string) {
        const tokenObject = this.generateAccessToken(user, type);
        this.res.status(200).send(Object.assign({},
            {message: 'Password has been changed'},
            tokenObject));
    }
}

class DeveloperForgotTokenController extends ForgotTokenController {
    public handler(): void {
        const result = this.validate(this.req.body);
        if (result) {
            this.errorHandler(result);
            return;
        }

        Developer.findOne({email: this.req.body.email}).exec()
            .then(this.checkToken.bind(this))
            .then(this.cryptPassword.bind(this))
            .then(this.saveUser.bind(this))
            .then(this.response.bind(this))
            .catch(this.errorHandler.bind(this));
    }

    protected response(user: IUserDocument) {
        super.response(user, 'developer');
    }
}

class RecruiterForgotTokenController extends ForgotTokenController {
    public handler(): void {
        const result = this.validate(this.req.body);
        if (result) {
            this.errorHandler(result);
            return;
        }

        Recruiter.findOne({email: this.req.body.email}).exec()
            .then(this.checkToken.bind(this))
            .then(this.cryptPassword.bind(this))
            .then(this.saveUser.bind(this))
            .then(this.response.bind(this))
            .catch(this.errorHandler.bind(this));
    }

    protected response(user: IUserDocument) {
        super.response(user, 'recruiter');
    }
}

/**
 * @swagger
 * definitions:
 *   ForgotToken:
 *     type: 'object'
 *     properties:
 *       token:
 *         type: 'string'
 *       email:
 *         type: 'string'
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
 *     - email
 *     - password
 *     - confirmPassword
 */

/**
 * @swagger
 * definitions:
 *   ForgotTokenResponse:
 *     type: 'object'
 *     properties:
 *       message:
 *         type: 'string'
 *       accessToken:
 *         type: string
 *       xsrfToken:
 *         type: string
 *     required:
 *     - message
 *     - accessToken
 *     - xsrfToken
 */

/**
 * @swagger
 * /auth/developer/forgot/token:
 *   post:
 *     summary: 'Forgot password, verify token from email and set new password'
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
 *           $ref: '#/definitions/ForgotToken'
 *     responses:
 *       200:
 *         description: 'Verify token and set new password successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/ForgotTokenResponse'
 */
export function developerForgotTokenHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const developerForgotTokenController = new DeveloperForgotTokenController(req, res, next);
    developerForgotTokenController.handler();
}

/**
 * @swagger
 * /auth/recruiter/forgot/token:
 *   post:
 *     summary: 'Forgot password, verify token from email and set new password'
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
 *           $ref: '#/definitions/ForgotToken'
 *     responses:
 *       200:
 *         description: 'Verify token and set new password successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/ForgotTokenResponse'
 */
export function recruiterForgotTokenHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const recruiterForgotTokenController = new RecruiterForgotTokenController(req, res, next);
    recruiterForgotTokenController.handler();
}
