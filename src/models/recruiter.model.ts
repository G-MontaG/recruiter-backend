import mongoose = require('mongoose');
import { IUserDocument, IUserModel, user, userSchema } from './user.model';

const Schema = mongoose.Schema;

const recruiterSchema = new Schema(Object.assign({}, user, {}), {timestamps: true});

export interface IRecruiterDocument extends IUserDocument {

}

export interface IRecruiterModel extends IUserModel {

}

recruiterSchema.methods = Object.assign({}, userSchema.methods, recruiterSchema.methods);

export const Recruiter = mongoose.model('Recruiter', recruiterSchema) as IRecruiterModel;
