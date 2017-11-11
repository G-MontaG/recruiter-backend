import express = require('express');
import Boom = require('boom');
import Joi = require('joi');
import { BaseController } from '../base.controller';
import { IUserDocument } from '../../models/user.model';
import { Developer } from '../../models/developer.model';
import { Recruiter } from '../../models/recruiter.model';
import { passwordMaxLength, passwordMinLength } from '../../helpers/constants';

abstract class SignUpController extends BaseController {
    protected readonly schema = Joi.object().keys({
        email: Joi.string().email(),
        password: Joi.string().regex(new RegExp(`^[a-zA-Z0-9]{${passwordMinLength},${passwordMaxLength}}$`))
    }).requiredKeys(['email', 'password']);

    protected checkUserExist(user: IUserDocument) {
        if (user) {
            throw Boom.conflict('Email is already in use');
        }
        const password = this.req.body.password;
        return password;
    }

    protected async abstract createUser(password: string): Promise<IUserDocument>

    protected async saveUser(newUser: IUserDocument) {
        await newUser.save();
        return newUser;
    }

    protected sendEmailVerification(newUser: IUserDocument) {
        const mailOptions = {
            to: newUser.email,
            from: 'arthur.osipenko@gmail.com',
            subject: 'Hello on XXX',
            text: `Hello. This is a token for your account 
                   ${newUser.emailVerifyToken.value}
                   Please go back and enter it in your profile to verify your email.`
        };
        //TODO: send email
        return newUser;
    }

    protected responseToken(newUser: IUserDocument, type: string) {
        const tokenObject = this.generateAccessToken(newUser, type);
        this.res.status(200).send(Object.assign({},
            {message: 'User is authorized'},
            tokenObject));
    }
}

class DeveloperSignUpController extends SignUpController {
    public handler() {
        const result = this.validate(this.req.body);
        if (result) {
            this.errorHandler(result);
            return;
        }

        Developer.findOne({email: this.req.body.email}).exec()
            .then(this.checkUserExist.bind(this))
            .then(this.createUser.bind(this))
            .then(this.saveUser.bind(this))
            .then(this.sendEmailVerification.bind(this))
            .then(this.responseToken.bind(this))
            .catch(this.errorHandler.bind(this));
    }

    protected async createUser(password: string) {
        const newUser = new Developer(this.req.body);
        newUser.createEmailVerifyToken();
        newUser.createRefreshToken();
        await newUser.cryptPassword(password);
        return newUser;
    }

    protected responseToken(newUser: IUserDocument) {
        super.responseToken(newUser, 'developer');
    }
}

class RecruiterSignUpController extends SignUpController {
    public handler() {
        const result = this.validate(this.req.body);
        if (result) {
            this.errorHandler(result);
            return;
        }

        Recruiter.findOne({email: this.req.body.email}).exec()
            .then(this.checkUserExist.bind(this))
            .then(this.createUser.bind(this))
            .then(this.saveUser.bind(this))
            .then(this.sendEmailVerification.bind(this))
            .then(this.responseToken.bind(this))
            .catch(this.errorHandler.bind(this));
    }

    protected async createUser(password: string) {
        const newUser = new Recruiter(this.req.body);
        newUser.createEmailVerifyToken();
        newUser.createRefreshToken();
        await newUser.cryptPassword(password);
        return newUser;
    }

    protected responseToken(newUser: IUserDocument) {
        super.responseToken(newUser, 'recruiter');
    }
}

/**
 * @swagger
 * definitions:
 *   SignUp:
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
 * /auth/developer/sign-up:
 *   post:
 *     summary: 'Sign-up to the application'
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
 *           $ref: '#/definitions/SignUp'
 *     responses:
 *       200:
 *         description: 'Sign-up successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/AuthTokenResponse'
 */
export function developerSignUpHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const developerSignUpController = new DeveloperSignUpController(req, res, next);
    developerSignUpController.handler();
}

/**
 * @swagger
 * /auth/recruiter/sign-up:
 *   post:
 *     summary: 'Sign-up to the application'
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
 *           $ref: '#/definitions/SignUp'
 *     responses:
 *       200:
 *         description: 'Sign-up successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/AuthTokenResponse'
 */
export function recruiterSignUpHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const recruiterSignUpController = new RecruiterSignUpController(req, res, next);
    recruiterSignUpController.handler();
}
