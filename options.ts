export const options = {
    remove_infected: false, // If true, removes infected files
    quarantine_infected: false, // False: Don't quarantine, Path: Moves files to this place.
    scan_log: null, // Path to a writeable log file to write scan results into
    debug_mode: false, // Whether or not to log info/debug/error msgs to the console
    file_list: null, // path to file containing list of files to scan (for scan_files method)
    scan_recursively: true, // If true, deep scan folders recursively
    clamscan: {
        path: '/usr/bin/clamscan', // Path to clamscan binary on your server
        db: null, // Path to a custom virus definition database
        scan_archives: true, // If true, scan archives (ex. zip, rar, tar, dmg, iso, etc...)
        active: true // If true, this module will consider using the clamscan binary
    },
    clamdscan: {
        path: '/usr/bin/clamdscan', // Path to the clamdscan binary on your server
        config_file: '/etc/clamd.conf', // Specify config file if it's in an unusual place
        multiscan: true, // Scan using all available cores! Yay!
        reload_db: false, // If true, will re-load the DB on every call (slow)
        active: true // If true, this module will consider using the clamdscan binary
    },
    preference: 'clamdscan' // If clamdscan is found and active, it will be used by default
}