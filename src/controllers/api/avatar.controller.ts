import express = require('express');
import Boom = require('boom');
import { BaseController } from '../base.controller';
import { avatarUploadMiddleware } from '../../middlewares/avatar.middleware';
import { cloudinaryConnection } from '../../db/cloudinary-connection';
import { IRequestWithUserId } from '../request.interface';

abstract class AvatarController extends BaseController {
    protected readonly req: IRequestWithUserId;

    public handler() {
        avatarUploadMiddleware(this.req, this.res, (err) => {
            if (err) {
                return this.errorHandler(Boom.boomify(err, {statusCode: 400}));
            }
            cloudinaryConnection.cloudinary.v2.uploader.upload_stream({
                    public_id: this.req.userId,
                    resource_type: 'image',
                    tags: ['developer'],
                    // here maybe front end send me information about user
                    // instead to fetching it from mongodb, witch expensive and not necessary here
                    context: {
                        alt: '',
                        caption: ''
                    },
                    width: 500,
                    height: 500,
                    crop: 'thumb',
                    format: 'png',
                    quality: 'auto:good'
                },
                (err: any, result: any) => {
                    if(err) {
                        return this.errorHandler(Boom.boomify(err, {statusCode: 400}));
                    }
                    this.response(result);
                }).end((<any>this.req).file.buffer);
        });
    }

    protected response(result: any) {
        this.res.status(200).send(result);
    }
}

class DeveloperAvatarController extends AvatarController {

}

class RecruiterAvatarController extends AvatarController {

}

/**
 * @swagger
 * definitions:
 *   AvatarResponse:
 *     type: 'object'
 *     properties:
 *       url:
 *         type: 'string'
 *     required:
 *     - url
 */

/**
 * @swagger
 * /api/developer/avatar:
 *   post:
 *     summary: 'Upload avatar'
 *     description: ''
 *     tags: [API, Developer]
 *     consumes:
 *       - multipart/form-data
 *     produces:
 *       - multipart/form-data
 *     parameters:
 *       - in: formData
 *         name: 'avatar'
 *         description: ''
 *         required: true
 *     responses:
 *       200:
 *         description: 'Avatar uploaded successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/AvatarResponse'
 *     security:
 *       - Authorization: []
 */
export function developerAvatarHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const developerAvatarController = new DeveloperAvatarController(req, res, next);
    developerAvatarController.handler();
}

/**
 * @swagger
 * /api/recruiter/avatar:
 *   post:
 *     summary: 'Upload avatar'
 *     description: ''
 *     tags: [API, Recruiter]
 *     consumes:
 *       - multipart/form-data
 *     produces:
 *       - multipart/form-data
 *     parameters:
 *       - in: formData
 *         name: 'avatar'
 *         description: ''
 *         required: true
 *     responses:
 *       200:
 *         description: 'Avatar uploaded successful'
 *         schema:
 *           type: 'object'
 *           $ref: '#/definitions/AvatarResponse'
 *     security:
 *       - Authorization: []
 */
export function recruiterAvatarHandler(req: express.Request, res: express.Response, next: express.NextFunction) {
    const recruiterAvatarController = new RecruiterAvatarController(req, res, next);
    recruiterAvatarController.handler();
}
