import express = require('express');

export interface IRouterConfiguration {
    type: string;
    route: string;
    handler: IHandlerFunction;
    middleware?: IMiddlewareFunction[];
}

export interface IHandlerFunction {
    (req: express.Request, res: express.Response, next: express.NextFunction): void;
}

export interface IMiddlewareFunction {
    (req: express.Request, res: express.Response, next: express.NextFunction): void;
}
