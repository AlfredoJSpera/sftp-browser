
const elProgressBar = $('#progressBar');
const elStatusBar = $('#statusBar');
const isElectron = window && window.process && window.process.type;
/** 
 * The hostname of the API
 * @type {string}
 */
let apiHost = window.localStorage.getItem('apiHost') || window.location.host;
let isLocalhost = window.location.hostname == 'localhost';
let httpProtocol = isLocalhost ? 'http' : 'https';
let wsProtocol = httpProtocol == 'http' ? 'ws' : 'wss';
/** An object of saved connection information */
let connections = JSON.parse(window.localStorage.getItem('connections')) || {};
/** The current active connection */
let activeConnection = null;
/** The ID of the current active connection */
let activeConnectionId = null;

/**
 * Checks if two HTML elements overlap
 * @param {HTMLElement} el1 The first element
 * @param {HTMLElement} el2 The second element
 * @returns {boolean} True if the elements overlap, false otherwise
 */
function checkDoElementsOverlap(el1, el2) {
    const rect1 = el1.getBoundingClientRect();
    const rect2 = el2.getBoundingClientRect();

    const overlap = !(rect1.right < rect2.left || 
                    rect1.left > rect2.right || 
                    rect1.bottom < rect2.top || 
                    rect1.top > rect2.bottom);

    return overlap;
}

const downloadUrl = (url, name) => {
    const a = document.createElement('a');
    a.href = url;
    a.download = name || '';
    a.click();
}

const getFileExtInfo = path => {
    const ext = path.split('.').pop().toLowerCase();
    const types = {
        image: {
            png: 'image/png',
            jpg: 'image/jpeg',
            jpeg: 'image/jpeg',
            gif: 'image/gif',
            svg: 'image/svg',
            webp: 'image/webp'
        },
        video: {
            mp4: 'video/mp4',
            webm: 'video/webm',
            ogv: 'video/ogg'
        },
        audio: {
            mp3: 'audio/mpeg',
            wav: 'audio/wav'
        },
        text: {
            txt: 'text/plain',
            html: 'text/html',
            css: 'text/css',
            js: 'text/javascript',
            json: 'application/json',
            py: 'text/x-python',
            php: 'text/x-php',
            java: 'text/x-java-source',
            c: 'text/x-c',
            cpp: 'text/x-c++',
            cs: 'text/x-csharp',
            rb: 'text/x-ruby',
            go: 'text/x-go',
            rs: 'text/x-rust',
            swift: 'text/x-swift',
            sh: 'text/x-shellscript',
            bat: 'text/x-batch',
            ps1: 'text/x-powershell',
            sql: 'text/x-sql',
            yaml: 'text/yaml',
            yml: 'text/yaml',
            ts: 'text/typescript',
            properties: 'text/x-properties',
        },
        markdown: {
            md: 'text/markdown',
            markdown: 'text/markdown'
        }
    };
    const data = { isViewable: false, type: null, mime: null }
    for (const type in types) {
        if (types[type][ext]) {
            data.isViewable = true;
            data.type = type;
            data.mime = types[type][ext];
            break;
        }
    }
    return data;
}

/**
 * Returns a boolean representing if the device has limited input capabilities (no hover and coarse pointer)
 */
const getIsMobileDevice = () => {
    const isPointerCoarse = window.matchMedia('(pointer: coarse)').matches;
    const isHoverNone = window.matchMedia('(hover: none)').matches;
    return isPointerCoarse && isHoverNone;
}

/**
 * Returns an object of headers for API requests that interface with the current active server
 */
const getHeaders = () => {
    const headers = {
        'sftp-host': activeConnection.host,
        'sftp-port': activeConnection.port,
        'sftp-username': activeConnection.username
    };
    if (activeConnection.password)
        headers['sftp-password'] = encodeURIComponent(activeConnection.password);
    if (activeConnection.key)
        headers['sftp-key'] = encodeURIComponent(activeConnection.key);
    return headers;
}

const api = {
    /**
     * Makes requests to the API
     * @param {'get'|'post'|'put'|'delete'} method The request method
     * @param {string} url The sub-URL of an API endpoint
     * @param {object|undefined} params An object of key-value query params
     * @param {*} body The body of the request, if applicable
     * @param {callback|undefined} onProgress A callback function that gets passed an Axios progress event
     * @returns {object} An object representing the response data or error info
     */
    request: async (method, url, params, body = null, onProgress = () => {}, responseType = 'json') => {
        url = `${httpProtocol}://${apiHost}/api/sftp/${url}`;
        try {
            const opts = {
                params, headers: getHeaders(),
                onUploadProgress: onProgress,
                onDownloadProgress: onProgress,
                responseType: responseType
            };
            let res = null;
            if (method == 'get' || method == 'delete') {
                res = await axios[method](url, opts);
            } else {
                res = await axios[method](url, body, opts);
            }
            //console.log(`Response from ${url}:`, res.data);
            return res.data;
        } catch (error) {
            if (responseType !== 'json') {
                console.error(error);
                return null;
            }
            if (error.response?.data) {
                console.warn(`Error ${error.response.status} response from ${url}:`, error.response.data);
                return error.response.data;
            } else {
                console.error(error);
                return {
                    success: false,
                    error: `${error}`
                };
            }
        }
    },
    get: (url, params) => api.request('get', url, params),
    post: (url, params, body) => api.request('post', url, params, body),
    put: (url, params, body) => api.request('put', url, params, body),
    delete: (url, params) => api.request('delete', url, params)
};

/**
 * Updates the bottom status bar.
 * @param {string} html The status text
 * @param {boolean} isError If `true`, turns the status red
 * @param {number|null} progress A 0-100 whole number to be used for the progress bar, or `null` to hide it
 * @returns {boolean} The negation of `isError`
 */
const setStatus = (html, isError = false, progress = null) => {
    elStatusBar.innerHTML = html;
    elStatusBar.classList.toggle('error', isError);
    elProgressBar.classList.remove('visible');
    if (progress !== null) {
        elProgressBar.classList.add('visible');
        elProgressBar.value = progress;
    }
    return !isError;
}

/**
 * Resolves with a download URL for a single file, or `false` if an error occurred.
 * @param {string} path The file path
 * @returns {Promise<string|boolean>}
 */
const getFileDownloadUrl = async path => {
    setStatus(`Getting single file download URL...`);
    const res = await api.get('files/get/single/url', {
        path: path
    });
    if (res.error) {
        return setStatus(`Error: ${res.error}`, true);
    }
    if (res.download_url) {
        return res.download_url;
    }
    return false;
}

/**
 * Starts a single-file download.
 * @param {string} path The file path
 */
const downloadFile = async path => {
    const url = await getFileDownloadUrl(path);
    if (url) {
        downloadUrl(url);
        setStatus(`Single file download started`);
    }
}