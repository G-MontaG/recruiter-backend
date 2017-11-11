import express = require('express');
import Boom = require('boom');
import Joi = require('joi');
import { BaseController } from '../base.controller';
import { IUserDocument } from '../../models/user.model';
import { Developer } from '../../models/developer.model';
import { Recruiter } from '../../models/recruiter.model';
import { passwordMaxLength, passwordMinLength } from '../../helpers/constants';

abstract class LoginController extends BaseController {
    protected readonly schema = Joi.object().keys({
        email: Joi.string().email(),
        password: Joi.string().regex(new RegExp(`^[a-zA-Z0-9]{${passwordMinLength},${passwordMaxLength}}$`))
    }).requiredKeys(['email', 'password']);

    protected checkUserExist(user: IUserDocument) {
        if (!user) {
            throw Boom.unauthorized('Email not found');
        }
        const password = this.req.body.password;
        return {user, password};
    }

    protected async checkPassword(params: {user: IUserDocument, password: string}) {
        const result = await params.user.checkPassword(params.password);
        return {user: params.user, result};
    }

    protected verifyResult(params: {user: IUserDocument, result: any}) {
        if (!params.result) {
            throw Boom.unauthorized('Incorrect password');
        }
        return {user: params.user};
    }

    protected responseToken(params: {user: IUserDocument}, type: string) {
        const tokenObject = this.generateAccessToken(params.user, type);
        this.res.status(200).send(Object.assign({},
            {message: 'User is authorized'},
            tokenObject));
    }
}

class DeveloperLoginController extends LoginController {
    public handler() {
        const result = this.validate(this.req.body);
        if (result) {
            this.errorHandler(result);
            return;
        }

        Developer.findOne({email: this.req.body.email}).exec()
            .then(this.checkUserExist.bind(this))
            .then(this.checkPassword.bind(this))
            .then(this.verifyResult.bind(this))
            .then(this.responseToken.bind(this))
            .catch(this.errorHandler.bind(this));
    }

    protected responseToken(params: any) {
        super.responseToken(params,'developer');
    }
}

class RecruiterLoginController extends LoginController {
    public handler() {
        const result = this.validate(this.req.body);
        if (result) {
            this.errorHandler(result);
            return;
        }

        Recruiter.findOne({email: this.req.body.email}).exec()
            .then(this.checkUserExist.bind(this))
            .then(this.checkPassword.bind(this))
            .then(this.verifyResult.bind(this))
            .then(this.responseToken.bind(this))
            .catch(this.errorHandler.bind(this));
    }

    protected responseToken(params: any) {
        super.responseToken(params,'recruiter');
    }
}

/**
 * @swagger
 * definitions:
 *   Login:
 *     type: 'object'
 *     properties:
 *       email:
 *         type: 'string'
 *       password:
 *         type: 'string'
 *         minLength: 8
 *         maxLength: 30
 *     required:
 *     - email
 *     - password
 */

/**
 * @swagger
 * /auth/developer/login:
 *   post:
 *     summary: 'Login to the application'
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
 *           $ref: '#/definitions/Login'
 *     responses:
 *       200:
 *         description: 'Login successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/AuthTokenResponse'
 */
export function developerLoginHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const developerLoginController = new DeveloperLoginController(req, res, next);
    developerLoginController.handler();
}

/**
 * @swagger
 * /auth/recruiter/login:
 *   post:
 *     summary: 'Login to the application'
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
 *           $ref: '#/definitions/Login'
 *     responses:
 *       200:
 *         description: 'Login successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/AuthTokenResponse'
 */
export function recruiterLoginHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const recruiterLoginController = new RecruiterLoginController(req, res, next);
    recruiterLoginController.handler();
}
