import multer  = require('multer');
const storage = multer.memoryStorage();
export const avatarUploadMiddleware = multer({
    storage: storage,
    fileFilter: function (req: any, file: any, cb: Function) {
        if (['image/png', 'image/jpeg', 'image/pjpeg'].indexOf(file.mimetype) === -1) {
            return cb(new Error('Wrong mimetype'), false);
        }
        cb(null, true);
    },
    limits: {
        fieldNameSize: 255,
        fileSize: 5 * 1000 * 1000,
        files: 1,
        fields: 1
    }
}).single('avatar');
