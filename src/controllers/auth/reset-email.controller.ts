import express = require('express');
import Boom = require('boom');
import { BaseController } from '../base.controller';
import { IUserDocument } from '../../models/user.model';
import { IRequestWithUserId } from '../request.interface';
import { Developer } from '../../models/developer.model';
import { Recruiter } from '../../models/recruiter.model';

abstract class ResetEmailController extends BaseController {
    protected readonly req: IRequestWithUserId;

    protected checkUserExist(user: IUserDocument) {
        if (!user) {
            throw Boom.unauthorized('User not found');
        }
        if (user.resetPasswordToken && user.resetPasswordToken.exp && !user.isResetPasswordTokenExpired()) {
            throw Boom.badRequest('Email was send');
        }
        return user;
    }

    protected generateToken(user: IUserDocument) {
        user.createResetPasswordToken();
        return user;
    }

    protected async saveUser(user: IUserDocument) {
        await user.save();
        return user;
    }

    protected sendResetEmailVerification(user: IUserDocument) {
        const mailOptions = {
            to: user.email,
            from: 'arthur.osipenko@gmail.com',
            subject: 'Reset password',
            text: `Hello. This is a token for your account 
                   ${user.resetPasswordToken.value}
                   Please go back and enter it in reset password form.`
        };
        //TODO: send email
        return user;
    }

    protected responseToken() {
        this.res.status(200).send({message: 'Token has been sent'});
    }
}

class DeveloperResetEmailController extends ResetEmailController {
    public handler() {
        Developer.findById(this.req.userId).exec()
            .then(this.checkUserExist.bind(this))
            .then(this.generateToken.bind(this))
            .then(this.saveUser.bind(this))
            .then(this.sendResetEmailVerification.bind(this))
            .then(this.responseToken.bind(this))
            .catch(this.errorHandler.bind(this));
    }
}

class RecruiterResetEmailController extends ResetEmailController {
    public handler() {
        Recruiter.findById(this.req.userId).exec()
            .then(this.checkUserExist.bind(this))
            .then(this.generateToken.bind(this))
            .then(this.saveUser.bind(this))
            .then(this.sendResetEmailVerification.bind(this))
            .then(this.responseToken.bind(this))
            .catch(this.errorHandler.bind(this));
    }
}

/**
 * @swagger
 * definitions:
 *   ResetEmailResponse:
 *     type: 'object'
 *     properties:
 *       message:
 *         type: 'string'
 *     required:
 *     - message
 */

/**
 * @swagger
 * /auth/developer/reset/email:
 *   post:
 *     summary: 'Reset password, send email token to verify user existing'
 *     description: ''
 *     tags: [Auth, Developer]
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: 'Send email token successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/ResetEmailResponse'
 */
export function developerResetEmailHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const developerResetEmailController = new DeveloperResetEmailController(req, res, next);
    developerResetEmailController.handler();
}

/**
 * @swagger
 * /auth/recruiter/reset/email:
 *   post:
 *     summary: 'Reset password, send email token to verify user existing'
 *     description: ''
 *     tags: [Auth, Recruiter]
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: 'Send email token successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/ResetEmailResponse'
 */
export function recruiterResetEmailHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const recruiterResetEmailController = new RecruiterResetEmailController(req, res, next);
    recruiterResetEmailController.handler();
}
