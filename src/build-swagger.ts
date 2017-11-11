import fs = require('fs');
import path = require('path');
import swaggerJSDoc = require('swagger-jsdoc');
const swaggerSpec = swaggerJSDoc({
    swaggerDefinition: {
        info: {
            title: 'Recruiter Swagger API',
            version: '1.0.0',
            description: 'Recruiter API',
            contacts: {
                name: 'Arthur',
                url: 'https://github.com/G-MontaG',
                email: 'arthur.osipenko@gmail.com'
            }
        },
        host: 'localhost',
        basePath: '/',
        schemes: ['https']
    },
    apis: ['./compiled/controllers/**/*.js'],
});
fs.writeFile(path.resolve('./swagger/swagger.json'), JSON.stringify(swaggerSpec), (err) => {
    if (err) {
        console.log(err);
    }
});
