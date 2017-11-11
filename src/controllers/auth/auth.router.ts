import { IRouterConfiguration } from '../router-configuration.interface';
import { BaseRouter } from '../base.router';
import { checkTokenMiddleware } from '../../middlewares/check-token.middleware';
import { developerSignUpHandler, recruiterSignUpHandler } from './sign-up.controller';
import { developerLoginHandler, recruiterLoginHandler } from './login.controller';
import { developerVerifyEmailHandler, recruiterVerifyEmailHandler } from './verify-email.controller';
import { developerForgotEmailHandler, recruiterForgotEmailHandler } from './forgot-email.controller';
import { developerForgotTokenHandler, recruiterForgotTokenHandler } from './forgot-token.controller';
import { developerResetEmailHandler, recruiterResetEmailHandler } from './reset-email.controller';
import { developerResetTokenHandler, recruiterResetTokenHandler } from './reset-token.controller';
import { logoutHandler } from './logout.controller';

class DeveloperAuthRouter extends BaseRouter {
    protected readonly configurations: IRouterConfiguration[] = [
        {type: 'post', route: '/sign-up', handler: developerSignUpHandler},
        {type: 'post', route: '/login', handler: developerLoginHandler},
        {
            type: 'post',
            route: '/verify-email',
            middleware: [checkTokenMiddleware],
            handler: developerVerifyEmailHandler
        },
        {type: 'post', route: '/forgot-email', handler: developerForgotEmailHandler},
        {type: 'post', route: '/forgot-token', handler: developerForgotTokenHandler},
        {type: 'post', route: '/reset-email', middleware: [checkTokenMiddleware], handler: developerResetEmailHandler},
        {type: 'post', route: '/reset-token', middleware: [checkTokenMiddleware], handler: developerResetTokenHandler},
        {type: 'get', route: '/logout', middleware: [checkTokenMiddleware], handler: logoutHandler}
    ];

    constructor() {
        super();
        this.configure();
    }
}

class RecruiterAuthRouter extends BaseRouter {
    protected readonly configurations: IRouterConfiguration[] = [
        {type: 'post', route: '/sign-up', handler: recruiterSignUpHandler},
        {type: 'post', route: '/login', handler: recruiterLoginHandler},
        {
            type: 'post',
            route: '/verify-email',
            middleware: [checkTokenMiddleware],
            handler: recruiterVerifyEmailHandler
        },
        {type: 'post', route: '/forgot-email', handler: recruiterForgotEmailHandler},
        {type: 'post', route: '/forgot-token', handler: recruiterForgotTokenHandler},
        {type: 'post', route: '/reset-email', middleware: [checkTokenMiddleware], handler: recruiterResetEmailHandler},
        {type: 'post', route: '/reset-token', middleware: [checkTokenMiddleware], handler: recruiterResetTokenHandler},
        {type: 'get', route: '/logout', middleware: [checkTokenMiddleware], handler: logoutHandler}
    ];

    constructor() {
        super();
        this.configure();
    }
}

/**
 * @swagger
 * tags:
 *   name: Auth
 *   description: 'Application authorization'
 */

/**
 * @swagger
 * securityDefinitions:
 *   Authorization:
 *     type: 'apiKey'
 *     name: 'Authorization'
 *     in: 'header'
 */

/**
 * @swagger
 * definitions:
 *   AuthTokenResponse:
 *     required:
 *       - message
 *       - accessToken
 *       - xsrfToken
 *     properties:
 *       message:
 *         type: string
 *       accessToken:
 *         type: string
 *       xsrfToken:
 *         type: string
 */
export const developerAuthRouter = new DeveloperAuthRouter();
export const recruiterAuthRouter = new RecruiterAuthRouter();
