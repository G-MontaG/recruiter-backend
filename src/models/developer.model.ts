import mongoose = require('mongoose');
import { IUserDocument, IUserModel, user, userSchema } from './user.model';

const Schema = mongoose.Schema;

const developerSchema = new Schema(Object.assign({}, user, {}), {timestamps: true});

export interface IDeveloperDocument extends IUserDocument {

}

export interface IDeveloperModel extends IUserModel {

}

developerSchema.methods = Object.assign({}, userSchema.methods, developerSchema.methods);

export const Developer = mongoose.model('Developer', developerSchema) as IDeveloperModel;
