module.exports = {
    apps: [
        {
            name: 'Recruiter API',
            cwd: "./compiled",
            script: 'app.js',
            instances: 1,
            exec_mode: 'cluster',
            watch: true,
            ignore_watch : ['node_modules'],
            watch_options: {
                followSymlinks: false
            },
            error_file: 'err.log',
            out_file: 'out.log',
            merge_logs: true,
            log_date_format: "YYYY-MM-DD HH:mm Z",
            env: {
                NODE_ENV: 'development'
            },
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
