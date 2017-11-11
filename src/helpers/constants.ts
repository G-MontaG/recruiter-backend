import crypto = require('crypto');
import fs = require('fs');
import path = require('path');

export const nodeID = crypto.randomBytes(32).toString('hex');

export const passwordMinLength = 8;
export const passwordMaxLength = 30;

export const tokenAlg = 'RS512';
export const tokenExp = 1; // days

export const privateKey = fs.readFileSync(path.resolve('./environment/jwtRSA512.key'));
export const publicKey = fs.readFileSync(path.resolve('./environment/jwtRSA512.pem'));

export const emailConfirmTokenLength = 8; // must be integer
export const emailConfirmTokenExp = 0.5; // hours

export const resetPasswordTokenLength = 8;
export const resetPasswordTokenExp = 0.5;

export const forgotPasswordTokenLength = 8;
export const forgotPasswordTokenExp = 0.5;

export const refreshTokenExp = 24;

export const expTimeAttempts = 1; // hours
