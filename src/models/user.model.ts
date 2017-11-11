import crypto = require('crypto');
import mongoose = require('mongoose');
import moment = require('moment');
import passwordGenerator = require('password-generator');
import {
    emailConfirmTokenExp,
    emailConfirmTokenLength,
    forgotPasswordTokenExp,
    forgotPasswordTokenLength,
    passwordMinLength,
    resetPasswordTokenExp,
    resetPasswordTokenLength,
    refreshTokenExp
} from '../helpers/constants';
import uuid = require('uuid');

const Schema = mongoose.Schema;

export const user = {
    email: {type: String, required: true, lowercase: true, unique: true, index: true},
    emailConfirmed: {type: Boolean, required: true, default: false},
    hash: {type: String},
    salt: {type: String},
    emailVerifyToken: {
        value: {type: String},
        exp: {type: Date}
    },
    resetPasswordToken: {
        value: {type: String},
        exp: {type: Date}
    },
    forgotPasswordToken: {
        value: {type: String},
        exp: {type: Date}
    },
    refreshToken: {
        value: {type: String},
        exp: {type: Date}
    },
    profile: {
        firstName: {type: String, default: ''},
        lastName: {type: String, default: ''},
        gender: {type: String, default: ''},
        language: {type: String, default: ''},
        picture: {
            url: {type: String, default: ''},
            source: {type: String, default: ''}
        }
    }
};

export const userSchema = new Schema(user);

export interface IUserDocument extends mongoose.Document {
    email: string;
    emailConfirmed: boolean;
    hash: string;
    salt: string;
    emailVerifyToken: {
        value: string,
        exp: Date
    };
    resetPasswordToken: {
        value: string,
        exp: Date
    };
    forgotPasswordToken: {
        value: string,
        exp: Date
    };
    refreshToken: {
        value: string,
        exp: Date
    };
    profile: {
        firstName: string,
        lastName: string,
        gender: string,
        language: string,
        picture: {
            url: string,
            source: string
        }
    };

    cryptPassword(password: string): Promise<void>;
    checkPassword(password: string): Promise<boolean>;
    createPassword(): string;

    createEmailVerifyToken(): void;
    setEmailConfirmed(): void;
    isEmailVerifyTokenEqual(emailVerifyToken: string): boolean;
    isEmailVerifyTokenExpired(): boolean;

    createResetPasswordToken(): void;
    setResetPasswordTokenUsed(): void;
    isResetPasswordTokenEqual(resetPasswordToken: string): boolean;
    isResetPasswordTokenExpired(): boolean;

    createForgotPasswordToken(): void;
    setForgotPasswordTokenUsed(): void;
    isForgotPasswordTokenEqual(forgotPasswordToken: string): boolean;
    isForgotPasswordTokenExpired(): boolean;

    createRefreshToken(): void;
    isRefreshTokenEqual(refreshToken: string): boolean;
    isRefreshTokenExpired(): boolean;
}

export interface IUserModel extends mongoose.Model<IUserDocument> {

}

// Generate hash based on <code>crypto.pbkdf2('sha512')</code> algorithm
function getHash(password: string, salt: string): Promise<string> {
    return new Promise((resolve, reject) => {
        if (!password || !salt) {
            reject(null);
        }
        const saltStr = salt;
        const length = 512;
        crypto.pbkdf2(password, saltStr, 50000, length, 'sha512', (err, hashStr) => {
            if (err) {
                reject(err);
            }
            resolve(hashStr.toString('base64'));
        });
    });
}

// Compare passwords based on their hashes
function compareHash(password: string, hash: string, salt: string): Promise<boolean | void> {
    if (!password || !hash || !salt) {
        return new Promise((resolve) => {resolve()});
    }
    return getHash(password, salt).then((generatedHash) => {
        return hash === generatedHash;
    });
}

userSchema.methods.cryptPassword = function(password: string): Promise<void> {
    this.salt = crypto.randomBytes(256).toString('base64');
    return getHash(password, this.salt).then((hash) => {
        this.hash = hash;
    });
};

userSchema.methods.checkPassword = function(password: string): Promise<boolean> {
    return compareHash(password, this.hash, this.salt).then((result: any) => {
        return result;
    });
};

userSchema.methods.createPassword = (): string => {
    return passwordGenerator(
        passwordMinLength,
        false,
        /[\w\d\W\!\@\#\$\%\^\&\*\(\)\=\_\+\,\.\/\<\>\?\;\'\:\"\|\{\}]/);
};

userSchema.methods.createEmailVerifyToken = function() {
    this.emailVerifyToken = {
        value: crypto.randomBytes(64).toString('base64').slice(0, emailConfirmTokenLength),
        exp: moment().add(emailConfirmTokenExp, 'hours').toDate()
    };
};

userSchema.methods.setEmailConfirmed = function(): void {
    this.emailConfirmed = true;
    this.emailVerifyToken = undefined;
};

userSchema.methods.isEmailVerifyTokenEqual = function(emailVerifyToken: string): boolean {
    return this.emailVerifyToken.value === emailVerifyToken;
};

userSchema.methods.isEmailVerifyTokenExpired = function(): boolean {
    return moment() > moment(this.emailVerifyToken.exp);
};

userSchema.methods.createResetPasswordToken = function() {
    this.resetPasswordToken = {
        value: crypto.randomBytes(64).toString('base64').slice(0, resetPasswordTokenLength),
        exp: moment().add(resetPasswordTokenExp, 'hours').toDate()
    };
};

userSchema.methods.setResetPasswordTokenUsed = function(): void {
    this.resetPasswordToken = undefined;
};

userSchema.methods.isResetPasswordTokenEqual = function(resetPasswordToken: string): boolean {
    return this.resetPasswordToken.value === resetPasswordToken;
};

userSchema.methods.isResetPasswordTokenExpired = function(): boolean {
    return moment() > moment(this.resetPasswordToken.exp);
};

userSchema.methods.createForgotPasswordToken = function() {
    this.forgotPasswordToken = {
        value: crypto.randomBytes(64).toString('base64').slice(0, forgotPasswordTokenLength),
        exp: moment().add(forgotPasswordTokenExp, 'hours').toDate()
    };
};

userSchema.methods.setForgotPasswordTokenUsed = function(): void {
    this.forgotPasswordToken = undefined;
};

userSchema.methods.isForgotPasswordTokenEqual = function(forgotPasswordToken: string): boolean {
    return this.forgotPasswordToken.value === forgotPasswordToken;
};

userSchema.methods.isForgotPasswordTokenExpired = function(): boolean {
    return moment() > moment(this.forgotPasswordToken.exp);
};

userSchema.methods.createRefreshToken = function() {
    this.refreshToken = {
        value: uuid.v4(),
        exp: moment().add(refreshTokenExp, 'hours').toDate()
    };
};

userSchema.methods.isRefreshTokenEqual = function(refreshToken: string): boolean {
    return this.refreshToken.value === refreshToken;
};

userSchema.methods.isRefreshTokenExpired = function(): boolean {
    return moment() > moment(this.refreshToken.exp);
};
