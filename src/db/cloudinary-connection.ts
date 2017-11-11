import cloudinary = require('cloudinary');

class CloudinaryConnection {
    public cloudinary = cloudinary;

    constructor() {
        cloudinary.config({
            cloud_name: process.env.CLOUDINARY_NAME,
            api_key: process.env.CLOUDINARY_API_KEY,
            api_secret: process.env.CLOUDINARY_API_SECRET
        });
    }
}

export const cloudinaryConnection = new CloudinaryConnection();
