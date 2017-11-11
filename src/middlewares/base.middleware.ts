import express = require('express');

export abstract class BaseMiddleware {
    protected readonly req: express.Request | any;
    protected readonly res: express.Response;
    protected readonly next: express.NextFunction;

    constructor(req: express.Request, res: express.Response, next: express.NextFunction) {
        this.req = req;
        this.res = res;
        this.next = next;
    }

    public abstract middleware(): void;

    protected errorHandler(err: any) {
        if (!err.isBoom) {
            this.next(err);
        }
        this.res.status(err.output.statusCode).send(err.output.payload);
    }
}
