module.exports = {
    apps: [
        {
            name: 'Recruiter API',
            cwd: "./compiled",
            script: 'app.js',
            instances: 4,
            exec_mode: 'cluster',
            watch: false,
            error_file: 'err.log',
            out_file: 'out.log',
            merge_logs: true,
            log_date_format: "YYYY-MM-DD HH:mm Z",
            env_production: {
                NODE_ENV: 'production'
            },
            max_restarts: 3,
            restart_delay: 1000,
            min_uptime: 5000,
            autorestart: true,
            'wait-ready': true,
            listen_timeout: 5000,
            kill_timeout: 10000
        }
    ],
};
