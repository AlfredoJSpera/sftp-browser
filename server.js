
const path = require('path');
const express = require('express');
const expressWs = require('express-ws');
const asyncHandler = require('express-async-handler');
const logger = require('cyber-express-logger');
const sftp = require('ssh2-sftp-client');
const crypto = require('crypto');
const mime = require('mime');
const bodyParser = require('body-parser');
const archiver = require('archiver');
const rawBodyParser = bodyParser.raw({
    limit: '16mb',
    type: '*/*'
});
const dayjs = require('dayjs');
const dayjsAdvancedFormat = require('dayjs/plugin/advancedFormat');
dayjs.extend(dayjsAdvancedFormat);
const utils = require('web-resources');
const Electron = require('electron');
const config = require('./config.json');

//============================//
//        GENERAL API         //
//============================//


/**
 * Normalizes a given file path to ensure it uses forward slashes
 * and removes any redundant slashes. 
 */
const normalizeRemotePath = remotePath => {
    remotePath = path.normalize(remotePath).replace(/\\/g, '/');
    const split = remotePath.split('/').filter(String);
    const joined = `/${split.join('/')}`;
    return joined;
};


/** Maps session hashes to SFTP session objects. */
const sessions = {};
/** Maps session hashes to the last activity timestamp. */
const sessionActivity = {};

/** Generates a SHA-256 hash for a given object. */
const getObjectHash = obj => {
    const hash = crypto.createHash('sha256');
    hash.update(JSON.stringify(obj));
    return hash.digest('hex');
}

/**
 * Manages SFTP sessions, either reusing existing ones or creating new ones.
 * @param {sftp.ConnectOptions} opts The SFTP connection parameters.
 * @returns {Promise<sftp>|null} The SFTP session object, or an error if the connection failed.
 */
const getSession = async (res, opts) => {
    const hash = getObjectHash(opts);
    const address = `${opts.username}@${opts.host}:${opts.port}`;

    // Check if a session already exists
    if (sessions[hash]) {
        console.log(`Using existing connection to ${address}`);
        sessionActivity[hash] = Date.now();
        return sessions[hash];
    }

    // Create a new session
    console.log(`Creating new connection to ${address}`);
    const session = new sftp();
    sessions[hash] = session;

    // Handle session events
    session.on('end', () => delete sessions[hash]);
    session.on('close', () => delete sessions[hash]);

    try {
        // Connect to the SFTP server
        await session.connect(opts);
        sessionActivity[hash] = Date.now();
    } catch (error) {
        delete sessions[hash];
        console.log(`Connection to ${address} failed`);
        return res ? res.sendError(error) : null;
    }

    return session;
};

/** Express server */
const srv = express();

// Express WebSocket middleware
expressWs(srv, undefined, {
    wsOptions: {
        maxPayload: 1024 * 1024 * 4
    }
});

srv.use(logger());

/** The directory of the `web` folder containing the static files */
const staticDir = path.join(__dirname, 'web');
srv.use(express.static(staticDir));

console.log(`Serving static files from ${staticDir}`);

/**
 * Initializes the API by: 
 * - setting up in the response object some custom methods to send data and errors
 * - validating request headers
 * - establishing an SFTP session
 */
const initApi = asyncHandler(async (req, res, next) => {
    // Custom method to send a JSON response with a specified status code
    res.sendData = (status = 200) => res.status(status).json(res.data);

    // Custom method to send an error JSON response
    res.sendError = (error, status = 400) => {
        res.data.success = false;
        res.data.error = `${error}`.replace('Error: ', '');
        res.sendData(status);
    }

    // Set the success flag to true by default
    res.data = {
        success: true
    };

    // Get the connection options from the request headers
    req.connectionOpts = {
        host: req.headers['sftp-host'],
        port: req.headers['sftp-port'] || 22,
        username: req.headers['sftp-username'],

        // Decode the password and private key from URI encoding
        password: decodeURIComponent(req.headers['sftp-password'] || '') || undefined,
        privateKey: decodeURIComponent(req.headers['sftp-key'] || '') || undefined,
    };

    // Validate the connection options
    if (!req.connectionOpts.host) {
        return res.sendError('Missing host header');
    }
    if (!req.connectionOpts.username) {
        return res.sendError('Missing username header');
    }
    if (!req.connectionOpts.password && !req.connectionOpts.privateKey) {
        return res.sendError('Missing password or key header');
    }

    // Get the SFTP session
    req.session = await getSession(res, req.connectionOpts);

    if (!req.session) {
        // If the session could not be created, 
        // the error has already been sent
        return;
    }

    next();
});

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//~~~~~~~~~MY CHANGES~~~~~~~~~//
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~//


let credentials = {}

srv.get('/api/sftp/credentials', async (req, res) => {
    res.json(credentials);
});

srv.get('/api/sftp/credentials/:id', async (req, res) => {
    const id = req.params.id;

    if (!credentials[id]) {
        res.status(404).json("Not found");
    } else {
        res.json(credentials[id]);
    }
});

srv.post('/api/sftp/credentials/create', rawBodyParser, async (req, res) => {
    const data = JSON.parse(req.body);
    const generatedId = crypto.randomUUID();

    let new_connection = {
        id: generatedId,
        name: data.name,
        host: data.host,
        port: data.port || 22,
        username: data.username,
        path: '/',
        createdTime: Date.now(),
    };

    key = data.key;
    password = data.password;

    if (key) {
        new_connection["key"] = key;
    } else if (password) {
        new_connection["password"] = password;
    } else {
        res.status(400).json("No key or password provided");
    }

    credentials[generatedId] = new_connection;
    res.json(new_connection);
})

srv.get('/api/sftp/credentials/delete/:id', async (req, res) => {
    const id = req.params.id;
    delete credentials[id];
    res.json(JSON.stringify({ success: true, status: 'complete' }));
});

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//~~~~~~~~~END MY CHANGES~~~~~~~~~//
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//


/** Stores the association between the generated keys and the corresponding requests */
const keyedRequests = {};

// Generates a random key and associates it with the incoming request
srv.get('/api/sftp/key', initApi, async (req, res) => {
    res.data.key = utils.randomHex(32);
    keyedRequests[res.data.key] = req;
    res.sendData();
});

//============================//
//      DIRECTORIES API       //
//============================//

// Get the list of files and directories in a given path on the SFTP server
srv.get('/api/sftp/directories/list', initApi, async (req, res) => {
    /** Obtained in `initApi` @type {sftp} */
    const session = req.session;
    res.data.path = normalizeRemotePath(req.query.path);

    // Whether to include files in the list or just directories
    res.data.includesFiles = req.query.dirsOnly === 'true' ? false : true;

    if (!res.data.path) {
        return res.sendError('Missing path', 400);
    }

    try {
        // Get the list of files and directories
        res.data.list = await session.list(res.data.path);

        if (res.data.list && !res.data.includesFiles) {
            // Filter out files if only directories are requested
            res.data.list = res.data.list.filter(item => item.type === 'd');
        }

        res.sendData();
    } catch (error) {
        res.sendError(error);
    }
});

// WebSocket endpoint to search for files and directories in a given path on the SFTP server
srv.ws('/api/sftp/directories/search', async (ws, wsReq) => {
    if (!wsReq.query.key) {
        return ws.close();
    }

    // Get the request associated with the key
    const req = keyedRequests[wsReq.query.key];

    if (!req) {
        return ws.close();
    }

    // Add uniqueness to the connection opts
    // This forces a new connection to be created
    req.connectionOpts.ts = Date.now();

    // Create the session and throw an error if it fails
    /** @type {sftp} */
    const session = await getSession(null, req.connectionOpts);
    const sessionHash = getObjectHash(req.connectionOpts);

    if (!session) {
        ws.send(JSON.stringify({
            success: false,
            error: 'Failed to create session!'
        }));
        return ws.close();
    }

    // Normalize the file path or throw an error if it's missing
    const filePath = normalizeRemotePath(wsReq.query.path);
    if (!filePath) {
        ws.send(JSON.stringify({
            success: false,
            error: 'Missing path'
        }));
        return ws.close();
    }

    // Get the query
    const query = wsReq.query.query;
    if (!query) {
        ws.send(JSON.stringify({
            success: false,
            error: 'Missing query'
        }));
        return ws.close();
    }

    // Update the session activity periodically to keep the session active
    const updateActivity = () => {
        sessionActivity[sessionHash] = Date.now();
    };

    let interval;
    interval = setInterval(updateActivity, 1000 * 1);

    // Handle websocket closure
    let isClosed = false;
    ws.on('close', () => {
        console.log(`Directory search websocket closed`);
        session.end();
        clearInterval(interval);
        delete sessionActivity[sessionHash];
        isClosed = true;
    });

    // Listen for messages
    console.log(`Websocket opened to search directory ${req.connectionOpts.username}@${req.connectionOpts.host}:${req.connectionOpts.port} ${filePath}`);

    /** Function to get a directory listing */
    const scanDir = async (dirPath) => {
        try {
            const list = await session.list(dirPath);
            return [...list].sort((a, b) => {
                // Sort by name
                if (a.name < b.name) return -1;
                if (a.name > b.name) return 1;
                return 0;
            });
        } catch (error) {
            return null;
        }
    };

    let matchedFiles = [];
    let lastSend = 0;
    /** Function to send a list when there are enough files */
    const sendList = () => {
        if (matchedFiles.length > 0) {
            ws.send(JSON.stringify({
                success: true,
                status: 'list',
                list: matchedFiles
            }));
            matchedFiles = [];
            lastSend = Date.now();
        }
    };

    /** Function to recursively search a directory */
    const recurse = async dirPath => {
        if (isClosed) return;
        ws.send(JSON.stringify({
            success: true,
            status: 'scanning',
            path: dirPath
        }));
        const list = await scanDir(dirPath);
        if (!list) {
            ws.send(JSON.stringify({
                success: false,
                error: `Failed to scan directory ${dirPath}`
            }));
            return;
        }
        for (const file of list) {
            if (isClosed) return;
            file.path = `${dirPath}/${file.name}`;
            if (file.name.toLowerCase().includes(query.toLowerCase())) {
                matchedFiles.push(file);
            }
            if ((Date.now() - lastSend) > 1000) sendList();
            if (file.type == 'd') {
                await recurse(file.path);
            }
        }
    };

    // Start the search
    await recurse(filePath);

    if (isClosed) {
        return;
    }

    sendList();

    // Send a complete message
    ws.send(JSON.stringify({ success: true, status: 'complete' }));

    // Close the websocket
    ws.close();
});

// Create a directory on the SFTP server
srv.post('/api/sftp/directories/create', initApi, async (req, res) => {
    /** Obtained in `initApi` @type {sftp} */
    const session = req.session;
    res.data.path = normalizeRemotePath(req.query.path);

    if (!res.data.path) {
        return res.sendError('Missing path', 400);
    }

    try {
        // Create the directory
        await session.mkdir(res.data.path);
        res.sendData();
    } catch (error) {
        res.sendError(error);
    }
});

// Delete a directory on the SFTP server
srv.delete('/api/sftp/directories/delete', initApi, async (req, res) => {
    /** Obtained in `initApi` @type {sftp} */
    const session = req.session;
    res.data.path = normalizeRemotePath(req.query.path);

    if (!res.data.path) {
        return res.sendError('Missing path', 400);
    }

    try {
        // Delete the directory
        await session.rmdir(res.data.path, true);
        res.sendData();
    } catch (error) {
        res.sendError(error);
    }
});

//============================//
//         FILES API          //
//============================//

// Check if a file or directory exists on the SFTP server and store it's type
srv.get('/api/sftp/files/exists', initApi, async (req, res) => {
    /** Obtained in `initApi` @type {sftp} */
    const session = req.session;
    res.data.path = normalizeRemotePath(req.query.path);

    if (!res.data.path) {
        return res.sendError('Missing path', 400);
    }

    try {
        const type = await session.exists(res.data.path);
        res.data.exists = type !== false;
        res.data.type = type;
        res.sendData();
    } catch (error) {
        res.sendError(error);
    }
});

// Create a file on the SFTP server
srv.post('/api/sftp/files/create', initApi, rawBodyParser, async (req, res) => {
    /** Obtained in `initApi` @type {sftp} */
    const session = req.session;
    res.data.path = normalizeRemotePath(req.query.path);

    if (!res.data.path) {
        return res.sendError('Missing path', 400);
    }

    try {
        // Upload the file to the specified path on the SFTP server
        await session.put(req.body, res.data.path);
        res.sendData();
    } catch (error) {
        res.sendError(error);
    }
});

// Append data to a file on the SFTP server
srv.put('/api/sftp/files/append', initApi, rawBodyParser, async (req, res) => {
    /** Obtained in `initApi` @type {sftp} */
    const session = req.session;
    res.data.path = normalizeRemotePath(req.query.path);

    if (!res.data.path) {
        return res.sendError('Missing path', 400);
    }

    try {
        // Append the data to the file
        await session.append(req.body, res.data.path);
        res.sendData();
    } catch (error) {
        res.sendError(error);
    }
});

// WebSocket endpoint to append data to a file on the SFTP server
srv.ws('/api/sftp/files/append', async (ws, wsReq) => {
    if (!wsReq.query.key)
        return ws.close();

    // Get the request associated with the key
    const req = keyedRequests[wsReq.query.key];

    if (!req) {
        return ws.close();
    }

    // Add uniqueness to the connection opts
    // This forces a new connection to be created
    req.connectionOpts.ts = Date.now();

    // Create the session and throw an error if it fails
    /** @type {sftp} */
    const session = await getSession(null, req.connectionOpts);
    const sessionHash = getObjectHash(req.connectionOpts);

    if (!session) {
        ws.send(JSON.stringify({
            success: false,
            error: 'Failed to create session!'
        }));
        return ws.close();
    }

    // Normalize the file path or throw an error if it's missing
    const filePath = normalizeRemotePath(wsReq.query.path);
    if (!filePath) {
        ws.send(JSON.stringify({
            success: false,
            error: 'Missing path'
        }));
        return ws.close();
    }

    // Handle websocket closure
    ws.on('close', () => {
        console.log(`File append websocket closed`);
        session.end();
        delete sessionActivity[sessionHash];
    });

    // Listen for messages
    console.log(`Websocket opened to append to ${req.connectionOpts.username}@${req.connectionOpts.host}:${req.connectionOpts.port} ${filePath}`);

    let isWriting = false;
    ws.on('message', async (data) => {
        // If we're already writing, send an error
        if (isWriting) {
            return ws.send(JSON.stringify({
                success: false,
                error: 'Writing in progress'
            }));
        }
        try {
            // Append the data to the file
            isWriting = true;
            await session.append(data, filePath);
            ws.send(JSON.stringify({ success: true }));
        } catch (error) {
            ws.send(JSON.stringify({
                success: false,
                error: error.toString()
            }));
            return ws.close();
        }
        isWriting = false;
        // Update the session activity
        sessionActivity[sessionHash] = Date.now();
    });

    // Send a ready message
    ws.send(JSON.stringify({ success: true, status: 'ready' }));
});

// Delete a file on the SFTP server
srv.delete('/api/sftp/files/delete', initApi, async (req, res) => {
    /** Obtained in `initApi` @type {sftp} */
    const session = req.session;
    res.data.path = normalizeRemotePath(req.query.path);

    if (!res.data.path) {
        return res.sendError('Missing path', 400);
    }

    try {
        // Delete the file
        await session.delete(res.data.path);
        res.sendData();
    } catch (error) {
        res.sendError(error);
    }
});

// Move a file on the SFTP server
srv.put('/api/sftp/files/move', initApi, async (req, res) => {
    /** Obtained in `initApi` @type {sftp} */
    const session = req.session;
    res.data.pathOld = normalizeRemotePath(req.query.pathOld);
    res.data.pathNew = normalizeRemotePath(req.query.pathNew);

    if (!res.data.pathOld) {
        return res.sendError('Missing source path', 400);
    }
    if (!res.data.pathNew) {
        return res.sendError('Missing destination path', 400);
    }

    try {
        // Move (or rename) the file
        await session.rename(res.data.pathOld, res.data.pathNew);
        res.sendData();
    } catch (error) {
        res.sendError(error);
    }
});

// Copy a file to a directory on the SFTP server
srv.put('/api/sftp/files/copy', initApi, async (req, res) => {
    /** Obtained in `initApi` @type {sftp} */
    const session = req.session;
    res.data.pathSrc = normalizeRemotePath(req.query.pathSrc);
    res.data.pathDest = normalizeRemotePath(req.query.pathDest);

    if (!res.data.pathSrc) {
        return res.sendError('Missing source path', 400);
    }
    if (!res.data.pathDest) {
        return res.sendError('Missing destination path', 400);
    }

    try {
        // Copy the file (or even a directory?)
        await session.rcopy(res.data.pathSrc, res.data.pathDest);
        res.sendData();
    } catch (error) {
        res.sendError(error);
    }
});

// Change the permissions of a file on the SFTP server
srv.put('/api/sftp/files/chmod', initApi, async (req, res) => {
    /** Obtained in `initApi` @type {sftp} */
    const session = req.session;
    res.data.path = normalizeRemotePath(req.query.path);

    if (!res.data.path) {
        return res.sendError('Missing path', 400);
    }

    res.data.mode = req.query.mode;

    try {
        // Change the permissions of the file
        await session.chmod(res.data.path, res.data.mode);
        res.sendData();
    } catch (error) {
        res.sendError(error);
    }
});

// Get the metadata of a file on the SFTP server
srv.get('/api/sftp/files/stat', initApi, async (req, res) => {
    /** Obtained in `initApi` @type {sftp} */
    const session = req.session;
    res.data.path = normalizeRemotePath(req.query.path);

    if (!res.data.path) {
        return res.sendError('Missing path', 400);
    }

    let stats = null;
    try {
        // Get the metadata of the file
        stats = await session.stat(res.data.path);
    } catch (error) {
        return res.sendError(error, 404);
    }

    res.data.stats = stats;
    res.sendData();
});

//============================//
//     DOWNLOAD HANDLERS      //
//============================//

/**
 * Handles the download of a single file from a remote SFTP server.
 *
 * @param {Object} connectionOpts - The connection options for the SFTP server.
 * @param {string} connectionOpts.host - The hostname of the SFTP server.
 * @param {number} connectionOpts.port - The port number of the SFTP server.
 * @param {string} connectionOpts.username - The username for the SFTP server.
 * @param {string} connectionOpts.password - The password for the SFTP server.
 * @param {Object} res - The HTTP response object.
 * @param {string} remotePath - The remote file path on the SFTP server.
 * @param {Object} stats - The file statistics object.
 * @param {boolean} stats.isFile - Indicates if the remote path is a file.
 * @param {number} stats.size - The size of the file in bytes.
 *
 * @throws {Error} If the remote path is not a file.
 * @throws {Error} If the session creation fails.
 */
const downloadSingleFileHandler = async (connectionOpts, res, remotePath, stats) => {
    let interval;

    try {
        if (!stats.isFile) {
            throw new Error('Not a file');
        }

        // Add uniqueness to the connection opts
        // This forces a new connection to be created
        connectionOpts.ts = Date.now();

        // Create the session and throw an error if it fails
        const session = await getSession(res, connectionOpts);
        if (!session) {
            throw new Error('Failed to create session');
        }

        // Continuously update the session activity
        interval = setInterval(() => {
            const hash = getObjectHash(connectionOpts);
            sessionActivity[hash] = Date.now();
        }, 1000 * 1);

        /** When the response closes, ends the session */
        const handleClose = () => {
            clearInterval(interval);
            session.end();
        };

        // On response close, end the session
        res.on('end', handleClose);
        res.on('close', handleClose);
        res.on('error', handleClose);

        // Set response headers
        res.setHeader('Content-Type', mime.getType(remotePath) || 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="${path.basename(remotePath)}"`);
        res.setHeader('Content-Length', stats.size);

        // Start the download
        console.log(`Starting download: ${connectionOpts.username}@${connectionOpts.host}:${connectionOpts.port} ${remotePath}`);
        await session.get(remotePath, res);

        // Force-end the response
        res.end();
    } catch (error) {
        // On error, clear the interval and send a 400 response
        clearInterval(interval);
        res.status(400).end();
    }
};

/**
 * Handles the downloading of multiple files from a remote server, compressing them into a zip archive.
 *
 * @param {Object} connectionOpts - The connection options for the remote server.
 * @param {string} connectionOpts.host - The hostname of the SFTP server.
 * @param {number} connectionOpts.port - The port number of the SFTP server.
 * @param {string} connectionOpts.username - The username for the SFTP server.
 * @param {string} connectionOpts.password - The password for the SFTP server.
 * @param {Object} res - The HTTP response object.
 * @param {string[]} remotePaths - An array of remote file paths to download.
 * @param {string} [rootPath='/'] - The root path to use for normalization.
 * @returns {Promise<void>} - A promise that resolves when the operation is complete.
 */
const downloadMultiFileHandler = async (connectionOpts, res, remotePaths, rootPath = '/') => {
    rootPath = normalizeRemotePath(rootPath);
    let interval;

    try {
        // Add uniqueness to the connection opts
        // This forces a new connection to be created
        connectionOpts.ts = Date.now();

        // Create the session and throw an error if it fails
        const session = await getSession(res, connectionOpts);
        if (!session) {
            throw new Error('Failed to create session');
        }

        // Continuously update the session activity
        setInterval(() => {
            const hash = getObjectHash(connectionOpts);
            sessionActivity[hash] = Date.now();
        }, 1000 * 1);

        // Set response headers
        let fileName = `Files (${path.basename(rootPath) || 'Root'})`;

        if (remotePaths.length == 1) {
            fileName = path.basename(remotePaths[0]);
        }

        res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fileName)}.zip"`);

        // Create the zip archive and start piping to the response
        const archive = archiver('zip');
        archive.pipe(res);

        /** When the response closes, end the session */
        const handleClose = () => {
            clearInterval(interval);
            archive.end();
            session.end();
        };

        // On response close, end the session
        res.on('end', handleClose);
        res.on('close', handleClose);
        res.on('error', handleClose);

        /** Adds a file to the zip archive */
        const addToArchive = async (remotePath) => {
            const archivePath = normalizeRemotePath(remotePath.replace(rootPath, ''));
            console.log(`Zipping: ${connectionOpts.username}@${connectionOpts.host}:${connectionOpts.port} ${remotePath}`);

            // Get file read stream
            const stream = session.createReadStream(remotePath);

            /** Waits for the operation to end */
            const waitToEnd = new Promise(resolve => {
                stream.on('end', resolve);
            });

            // Add file to archive
            archive.append(stream, {
                name: archivePath
            });

            await waitToEnd;
        };

        /** Recurse through directories and archive files */
        const recurse = async (remotePath) => {
            try {
                const stats = await session.stat(remotePath);
                if (stats.isFile) {
                    await addToArchive(remotePath);
                } else if (stats.isDirectory) {
                    const list = await session.list(remotePath);
                    for (const item of list) {
                        const subPath = `${remotePath}/${item.name}`;
                        if (item.type === '-') {
                            await addToArchive(subPath);
                        } else {
                            await recurse(subPath);
                        }
                    }
                }
            } catch (error) { }
        };

        for (const remotePath of remotePaths) {
            await recurse(remotePath);
        }

        // Finalize the archive
        archive.on('close', () => res.end());
        archive.finalize();
    } catch (error) {
        clearInterval(interval);
        res.status(400).end();
    }
};

//============================//
//        DOWNLOAD API        //
//============================//


// Download a single file from the SFTP server
srv.get('/api/sftp/files/get/single', initApi, async (req, res) => {
    /** Obtained in `initApi` @type {sftp} */
    const session = req.session;

    // Get the normalized path and throw an error if it's missing
    const remotePath = normalizeRemotePath(req.query.path);
    if (!remotePath) {
        return res.sendError('Missing path', 400);
    }

    try {
        // Get the file metadata and download it
        const stats = await session.stat(remotePath);
        await downloadSingleFileHandler(req.connectionOpts, res, remotePath, stats);
    } catch (error) {
        res.status(400).end();
    }
});

/** Stores the raw download handlers */
const rawDownloads = {};

// Download a single file from the SFTP server and get a URL
srv.get('/api/sftp/files/get/single/url', initApi, async (req, res) => {
    /** Obtained in `initApi` @type {sftp} */
    const session = req.session;

    // Get the normalized path and throw an error if it's missing
    res.data.path = normalizeRemotePath(req.query.path);
    if (!res.data.path) {
        return res.sendError('Missing path', 400);
    }

    // Get path stats and throw an error if it's not a file
    let stats = null;
    try {
        stats = await session.stat(res.data.path);
        if (!stats?.isFile) throw new Error('Not a file');
    } catch (error) {
        return res.sendError(error);
    }

    // Generate download URL
    const id = utils.randomHex(8);
    res.data.download_url = `https://${req.get('host')}/dl/${id}`;

    // Create download handler
    rawDownloads[id] = {
        created: Date.now(),
        paths: [res.data.path],
        handler: async (req2, res2) => {
            await downloadSingleFileHandler(req.connectionOpts, res2, res.data.path, stats);
        }
    }
    res.sendData();
});

// Download multiple files from the SFTP server and get a URL
srv.get('/api/sftp/files/get/multi/url', initApi, async (req, res) => {
    try {
        // Get the normalized path and throw an error if it's missing
        res.data.paths = JSON.parse(req.query.paths);
        if (!res.data.paths) {
            throw new Error('Missing path(s)');
        }
    } catch (error) {
        return res.sendError(error);
    }

    // Generate download URL
    const id = utils.randomHex(8);
    res.data.download_url = `https://${req.get('host')}/dl/${id}`;

    // Create download handler
    rawDownloads[id] = {
        created: Date.now(),
        paths: res.data.paths,
        isZip: true,
        handler: async (req2, res2) => {
            await downloadMultiFileHandler(req.connectionOpts, res2, res.data.paths, req.query.rootPath);
        }
    }
    res.sendData();
});

// Process download requests
srv.get('/dl/:id', async (req, res) => {
    /** Download handler */
    const entry = rawDownloads[req.params.id];

    if (!entry) {
        return res.status(404).end();
    }

    // If the user agent looks like a bot
    if (req.get('user-agent').match(/(bot|scrape)/)) {
        // Send some HTML
        res.setHeader('Content-Type', 'text/html');
        const html = /*html*/`
            <html>
                <head>
                    <title>Download shared files</title>
                    <meta property="og:site_name" content="SFTP Browser" />
                    <meta property="og:title" content="Shared ${entry.isZip ? 'files' : 'file'}" />
                    <meta property="og:description" content="Click to download ${entry.isZip ? `these files compressed into a zip.` : `${path.basename(entry.paths[0])}.`} This link will expire on ${dayjs(entry.created + (1000 * 60 * 60 * 24)).format('YYYY-MM-DD [at] hh:mm:ss ([GMT]Z)')}." />
                    <meta name="theme-color" content="#1f2733">
                    <meta property="og:image" content="https://${req.get('host')}/icon.png" />
                </head>
                <body>
                    <p>Click <a href="${req.originalUrl}">here</a> to download the file.</p>
                </body>
            </html>
        `;
        res.send(html);
    } else {
        entry.handler(req, res);
    }
});

//============================//
//           OTHER            //
//============================//

// Error for non-existent API routes
srv.use((req, res) => res.status(404).end());

// Delete inactive sessions and downloads
setInterval(() => {
    // Inactive sessions
    for (const hash in sessions) {
        const lastActive = sessionActivity[hash];
        if (!lastActive) continue;
        if ((Date.now() - lastActive) > 1000 * 60 * 5) {
            console.log(`Deleting inactive sftp session`);
            sessions[hash].end();
            delete sessions[hash];
            delete sessionActivity[hash];
        }
    }

    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
    //~~~~~~~~~MY CHANGES~~~~~~~~~//
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~//

    // Inactive credential objects
    for (const credential in credentials) {
        if ((Date.now() - credential.createdTime) > 1000 * 60 * 1) {
            console.log(`Deleting unused credentials ${id}`);
            delete credentials[id];
        }
    }

    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
    //~~~~~~~~~END MY CHANGES~~~~~~~~~//
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//

    // Unused downloads
    for (const id in rawDownloads) {
        const download = rawDownloads[id];
        if ((Date.now() - download.created) > 1000 * 60 * 60 * 12) {
            console.log(`Deleting unused download`);
            delete rawDownloads[id];
        }
    }
}, 1000 * 30);

//============================//
//          ELECTRON          //
//============================//

if (Electron.app) {
    Electron.app.whenReady().then(async () => {
        // Start the server
        let port = 8001 + Math.floor(Math.random() * 999);
        await new Promise(resolve => {
            srv.listen(port, () => {
                console.log(`App server listening on port ${port}`)
                resolve();
            });
        });
        // Open the window
        const window = new Electron.BrowserWindow({
            width: 1100,
            height: 720,
            autoHideMenuBar: true,
            minWidth: 320,
            minHeight: 200
        });
        window.loadURL(`http://localhost:${port}`);
        // Quit the app when all windows are closed
        // unless we're on macOS
        Electron.app.on('window-all-closed', () => {
            if (process.platform !== 'darwin') Electron.app.quit();
        });
    });
} else {
    srv.listen(config.port, () => console.log(`Standalone server listening on http://localhost:${config.port}`));
}