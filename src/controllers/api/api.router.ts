import { IRouterConfiguration } from '../router-configuration.interface';
import { checkTokenMiddleware } from '../../middlewares/check-token.middleware';
import { BaseRouter } from '../base.router';
import {
    developerDictionaryLocationHandler,
    recruiterDictionaryLocationHandler
} from './dictionary/location.controller';
import { developerAvatarHandler, recruiterAvatarHandler } from './avatar.controller';

class DeveloperApiRouter extends BaseRouter {
    protected readonly configurations: IRouterConfiguration[] = [
        {
            type: 'get',
            route: '/dictionary/location',
            middleware: [checkTokenMiddleware],
            handler: developerDictionaryLocationHandler
        },
        {
            type: 'post',
            route: '/avatar',
            middleware: [checkTokenMiddleware],
            handler: developerAvatarHandler
        }
    ];

    constructor() {
        super();
        this.configure();
    }
}

class RecruiterApiRouter extends BaseRouter {
    protected readonly configurations: IRouterConfiguration[] = [
        {
            type: 'get',
            route: '/dictionary/location',
            middleware: [checkTokenMiddleware],
            handler: recruiterDictionaryLocationHandler
        },
        {
            type: 'post',
            route: '/avatar',
            middleware: [checkTokenMiddleware],
            handler: recruiterAvatarHandler
        }
    ];

    constructor() {
        super();
        this.configure();
    }
}

/**
 * @swagger
 * tags:
 *   name: API
 *   description: 'Application API'
 */
export const developerApiRouter = new DeveloperApiRouter();
export const recruiterApiRouter = new RecruiterApiRouter();
