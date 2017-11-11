module.exports = {
    apps: [
        {
            name: 'Recruiter API',
            cwd: "./compiled",
            script: 'app.js',
            instances: 1,
            exec_mode: 'fork',
            watch: false,
            error_file: 'err.log',
            out_file: 'out.log',
            merge_logs: true,
            log_date_format: "YYYY-MM-DD HH:mm Z",
            env: {
                NODE_ENV: 'debug'
            },
            node_args: '--inspect',
            max_restarts: 3,
            restart_delay: 1000,
            min_uptime: 5000,
            autorestart: false,
            'wait-ready': true,
            listen_timeout: 5000,
            kill_timeout: 10000
        }
    ],
};
