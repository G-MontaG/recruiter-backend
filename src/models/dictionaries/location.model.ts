import fs = require('fs');
import path = require('path');
import mongoose = require('mongoose');

const Schema = mongoose.Schema;
import winston = require('winston');

const locations = fs.readFileSync(path.resolve('./dump/locations.json')).toString();

const locationSchema = new Schema({
    text: {type: String, required: true}
}, {versionKey: false});

export interface ILocationDocument extends mongoose.Document {
    text: string;
}

export interface ILocationModel extends mongoose.Model<ILocationDocument> {

}

export const DictionaryLocation = mongoose.model('Dictionary:Location', locationSchema) as ILocationModel;

DictionaryLocation.collection.drop();
DictionaryLocation.insertMany(JSON.parse(locations)).then((docs) => {
    winston.log('info', `Locations imported`);
}).catch((err) => winston.log('error', err));
