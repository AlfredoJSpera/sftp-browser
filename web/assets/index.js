
const btnConnections = $('#connections');
const btnNavBack = $('#navBack');
const btnNavForward = $('#navForward');
const inputNavPath = $('#inputNavPath');
const btnGo = $('#pathGo');
const btnPathPopup = $('#pathPopup');
const elBelowNavBar = $('#belowNavBar');
const btnDirMenu = $('#dirMenu');
const btnDeselectAll = $('#deselectAll');
const btnUpload = $('#upload');
const btnDirCreate = $('#dirCreate');
const btnSelectionCut = $('#fileCut');
const btnSelectionCopy = $('#fileCopy');
const btnSelectionPaste = $('#filePaste');
const btnRename = $('#fileRename');
const btnSelectionMoveTo = $('#fileMoveTo');
const btnSelectionCopyTo = $('#fileCopyTo');
const btnSelectionDelete = $('#fileDelete');
const btnDownload = $('#fileDownload');
const btnShare = $('#fileShare');
const btnDirSort = $('#dirSort');
const btnDirView = $('#dirView');
const btnDirSelection = $('#dirSelection');
const elFileColHeadings = $('#fileColHeadings');
const elFiles = $('#files');
const forceTileViewWidth = 720;
/** An array of paths in the back history */
let backPaths = [];
/** An array of paths in the forward history */
let forwardPaths = [];
/** An array of paths cut or copied to the clipboard */
let selectionClipboard = [];
/** True the clipboard paste mode is cut */
let isClipboardCut = false;
/**
 * The current file sort order
 * @type {'name'|'size'|'date'}
 */
let sortType = window.localStorage.getItem('sortType') || 'name';
/** 
 * True of the file sort order is to be reversed
 * @type {boolean}
 */
let sortDesc = window.localStorage.getItem('sortDesc');
sortDesc = (sortDesc == null) ? false : (sortDesc === 'true');
/** 
 * True of hidden files should be visible
 * @type {boolean}
 */
let showHidden = window.localStorage.getItem('showHidden');
showHidden = (showHidden == null) ? true : (showHidden === 'true');
/**
 * The current file view mode
 * @type {'list'|'tile'}
 */
let viewMode = window.localStorage.getItem('viewMode') || 'list';
/** True if an upload is in progress */
let isUploading = false;
/** The index of the most recently selected file, or -1 if no files are selected */
let lastSelectedIndex = -1;
/** True of a directory load is in progress
 * and currently visible files shouldn't be accessed */
let fileAccessLock = false;

/**
 * Saves the current state of the `connections` object to LocalStorage.
 */
const saveConnections = () => {
    window.localStorage.setItem('connections', JSON.stringify(connections));
}

/**
 * Opens a dialog popup to manage stored connection information.
 */
const connectionManagerDialog = () => {
    const popup = new PopupBuilder();
    const el = document.createElement('div');
    el.id = 'connectionManager';
    el.classList = 'col gap-15';
    for (const id in connections) {
        const connection = connections[id];
        const entry = document.createElement('div');
        entry.classList = 'entry row gap-10 align-center';
        entry.innerHTML = /*html*/`
            <div class="icon flex-no-shrink">cloud</div>
            <div class="row flex-wrap align-center flex-grow">
                <div class="col gap-5 flex-grow">
                    <div class="label">${connection.name}</div>
                    <small>
                        ${connection.username}@${connection.host}:${connection.port}
                        <br>${connection.path}
                    </small>
                </div>
                <div class="row gap-10">
                    <button class="menu btn iconOnly small secondary" title="Connection options">
                        <div class="icon">more_vert</div>
                    </button>
                    <button class="connect btn iconOnly small" title="Connect">
                        <div class="icon">arrow_forward</div>
                    </button>
                </div>
            </div>
        `;
        $('.btn.menu', entry).addEventListener('click', () => {
            new ContextMenuBuilder()
                .addItem(option => option
                    .setLabel('Edit...')
                    .setIcon('edit')
                    .setClickHandler(async() => {
                        popup.hide();
                        await editConnectionDialog(id);
                        connectionManagerDialog();
                    }))
                .addItem(option => option
                    .setLabel('Export...')
                    .setIcon('download')
                    .setClickHandler(async() => {
                        const exportBody = document.createElement('div');
                        exportBody.classList = 'col gap-10';
                        exportBody.style.maxWidth = '400px';
                        exportBody.innerHTML = /*html*/`
                            <label class="selectOption">
                                <input type="radio" name="exportCredentials" value="exclude" checked>
                                Without credentials
                            </label>
                            <label class="selectOption">
                                <input type="radio" name="exportCredentials" value="include">
                                With private key or password
                            </label>
                            <small style="color: var(--red3)">Only share exports with credentials with people you trust! These credentials grant access to not only your server's files, but oftentimes an interactive terminal (SSH).</small>
                        `;
                        new PopupBuilder()
                            .setTitle(`Export ${connection.name}`)
                            .addBody(exportBody)
                            .addAction(action => action
                                .setLabel('Export')
                                .setIsPrimary(true)
                                .setClickHandler(() => {
                                    const includeCredentials = $('input[name="exportCredentials"]:checked', exportBody).value == 'include';
                                    const data = {
                                        name: connection.name,
                                        host: connection.host,
                                        port: connection.port,
                                        username: connection.username,
                                        path: connection.path
                                    };
                                    if (includeCredentials) {
                                        if (connection.key)
                                            data.key = connection.key;
                                        if (connection.password)
                                            data.password = connection.password;
                                    }
                                    const blob = new Blob([
                                        JSON.stringify(data)
                                    ], {
                                        type: 'application/json'
                                    });
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement('a');
                                    a.href = url;
                                    a.download = `${connection.name.replace(/[^a-zA-Z-_\. ]/g, '').trim() || 'connection'}.json`;
                                    a.click();
                                    URL.revokeObjectURL(url);
                                }))
                            .addAction(action => action.setLabel('Cancel'))
                            .show();
                    }))
                .addSeparator()
                .addItem(option => option
                    .setLabel('Delete')
                    .setIcon('delete')
                    .setIsDanger(true)
                    .setClickHandler(async() => {
                        delete connections[id];
                        saveConnections();
                        entry.remove();
                    }))
                .showAtCursor();
        });
        $('.btn.connect', entry).addEventListener('click', () => {
            popup.hide();
            setActiveConnection(id);
        });
        el.appendChild(entry);
    }
    const btnsCont = document.createElement('div');
    btnsCont.classList = 'row gap-10 flex-wrap';
    const btnAdd = document.createElement('button');
    btnAdd.classList = 'btn success small';
    btnAdd.innerHTML = /*html*/`
        <div class="icon">add</div>
        New connection...
    `;
    btnAdd.addEventListener('click', async() => {
        popup.hide();
        await addNewConnectionDialog();
        connectionManagerDialog();
    });
    btnsCont.appendChild(btnAdd);
    const btnImport = document.createElement('button');
    btnImport.classList = 'btn secondary small';
    btnImport.innerHTML = /*html*/`
        <div class="icon">cloud_upload</div>
        Import...
    `;
    btnImport.addEventListener('click', async() => {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.json';
        input.addEventListener('change', async() => {
            const file = input.files[0];
            if (!file) return;
            popup.hide();
            const reader = new FileReader();
            reader.addEventListener('load', async() => {
                const data = JSON.parse(reader.result);
                const id = Date.now();
                connections[id] = data;
                saveConnections();
                if (!data.key && !data.password) {
                    return editConnectionDialog(id);
                }
                connectionManagerDialog();
            });
            reader.readAsText(file);
        });
        input.click();
    });
    btnsCont.appendChild(btnImport);
    el.appendChild(btnsCont);
    popup
        .setTitle('Connections')
        .addBody(el)
        .addAction(action => action
            .setIsPrimary(true)
            .setLabel('Done')
            .setClickHandler(() => {
                saveConnections();
            }));
    popup.show();
}

/**
 * Opens a dialog to edit an existing connection by its ID.
 * @param {number} id The connection ID
 * @returns {Promise<number>} Resolves with the ID passed in
 */
const editConnectionDialog = async (id) => new Promise(resolve => {
    const connection = connections[id];
    if (!connection) throw new Error(`Connection with ID ${id} not found!`);
    const securityNote = thing => `Your ${thing} is saved in this browser and only persists on the server during and for a few minutes after each request.`;
    const el = document.createElement('div');
    el.classList = 'col gap-10';
    el.innerHTML = /*html*/`
        <div style="width: 300px; max-width: 100%">
            <label>Friendly name</label>
            <input type="text" class="textbox" id="inputName" value="${connection.name}" placeholder="My Server">
        </div>
        <div class="row gap-10 flex-wrap">
            <div style="width: 300px; max-width: 100%">
                <label>Host</label>
                <input type="text" class="textbox" id="inputHost" value="${connection.host}" placeholder="example.com">
            </div>
            <div style="width: 120px; max-width: 100%">
                <label>Port</label>
                <input type="number" class="textbox" id="inputPort" value="${connection.port}" placeholder="22">
            </div>
        </div>
        <div style="width: 200px; max-width: 100%">
            <label>Username</label>
            <input type="text" class="textbox" id="inputUsername" value="${connection.username}" placeholder="kayla">
        </div>
        <div style="width: 300px; max-width: 100%">
            <label>Authentication</label>
            <div class="row gap-10 flex-wrap">
                <label class="selectOption">
                    <input id="authTypePassword" type="radio" name="authType" value="password">
                    Password
                </label>
                <label class="selectOption">
                    <input id="authTypeKey" type="radio" name="authType" value="key">
                    Private key
                </label>
            </div>
        </div>
        <div id="passwordCont" style="width: 300px; max-width: 100%" class="col gap-5">
            <input type="password" class="textbox" id="inputPassword" value="${connection.password || ''}" placeholder="Password">
            <small>${securityNote('password')}</small>
        </div>
        <div id="keyCont" class="col gap-5" style="width: 500px; max-width: 100%">
            <div class="row">
                <button id="loadKeyFromFile" class="btn secondary small">
                    <div class="icon">key</div>
                    Load from file
                </button>
            </div>
            <div class="textbox textarea">
                <textarea id="inputKey" placeholder="Private key..." rows="5">${connection.key || ''}</textarea>
            </div>
            <small>Your private key is typically located under <b>C:\\Users\\you\\.ssh</b> on Windows, or <b>/home/you/.ssh</b> on Unix. It's not the ".pub" file! The server has to be configured to accept your public key for your private one to work.</small>
            <small>${securityNote('private key')}</small>
        </div>
        <div style="width: 300px; max-width: 100%">
            <label>Starting path</label>
            <input type="text" class="textbox" id="inputPath" value="${connection.path}" placeholder="/home/kayla">
        </div>
    `;
    const inputName = $('#inputName', el);
    const inputHost = $('#inputHost', el);
    const inputPort = $('#inputPort', el);
    const inputUsername = $('#inputUsername', el);
    const authTypePassword = $('#authTypePassword', el);
    const authTypeKey = $('#authTypeKey', el);
    const inputPassword = $('#inputPassword', el);
    const elPasswordCont = $('#passwordCont', el);
    const elKeyCont = $('#keyCont', el);
    const inputKey = $('#inputKey', el);
    const btnLoadKey = $('#loadKeyFromFile', el);
    const inputPath = $('#inputPath', el);
    authTypePassword.addEventListener('change', () => {
        elPasswordCont.style.display = '';
        elKeyCont.style.display = 'none';
    });
    authTypeKey.addEventListener('change', () => {
        elPasswordCont.style.display = 'none';
        elKeyCont.style.display = '';
    });
    if (!connection.password && !connection.key) {
        authTypeKey.checked = true;
        authTypeKey.dispatchEvent(new Event('change'));
    } else if (!connection.password) {
        authTypeKey.checked = true;
        authTypeKey.dispatchEvent(new Event('change'));
    } else {
        authTypePassword.checked = true;
        authTypePassword.dispatchEvent(new Event('change'));
    }
    btnLoadKey.addEventListener('click', () => {
        const input = document.createElement('input');
        input.type = 'file';
        input.addEventListener('change', () => {
            const file = input.files[0];
            if (file.size > 1024) return;
            const reader = new FileReader();
            reader.addEventListener('load', () => {
                inputKey.value = reader.result;
            });
            reader.readAsText(file);
        });
        input.click();
    });
    const popup = new PopupBuilder()
        .setTitle('Edit connection')
        .addBody(el);
    popup.addAction(action => action
        .setIsPrimary(true)
        .setLabel('Save')
        .setClickHandler(() => {
            connection.host = inputHost.value;
            connection.port = inputPort.value || 22;
            connection.username = inputUsername.value;
            connection.name = inputName.value || `${connection.username}@${connection.host}`;
            if (authTypePassword.checked) {
                connection.password = inputPassword.value;
                delete connection.key;
            } else {
                connection.key = inputKey.value;
                delete connection.password;
            }
            connection.path = inputPath.value;
            saveConnections();
        }));
    popup.addAction(action => action.setLabel('Cancel'));
    popup.show();
    popup.setOnHide(() => resolve(id));
});

/**
 * Adds a new connection with basic placeholder data and runs `editConnectionDialog()` on it.
 */
const addNewConnectionDialog = async() => {
    const id = Date.now();
    connections[id] = {
        name: 'New Connection',
        host: '',
        port: 22,
        username: '',
        key: '',
        password: '',
        path: '/'
    };
    await editConnectionDialog(id);
    if (!connections[id].host || !connections[id].username) {
        delete connections[id];
    }
}

/**
 * Sets the active connection to the one with the specified ID.
 * @param {number} id The connection ID
 * @param {string} path An initial directory path to override the saved one
 */
const setActiveConnection = (id, path) => {
    if (!connections[id]) {
        throw new Error(`Connection with ID ${id} not found!`);
    }
    backPaths = [];
    forwardPaths = [];
    activeConnection = JSON.parse(JSON.stringify(connections[id]));
    activeConnectionId = id;
    selectionClipboard = [];
    changePath(path, false);
}

/**
 * Changes the path and loads the directory or file.
 * @param {string} path The target path
 * @param {boolean} pushState If `true`, update the back/forward history
 */
const changePath = async(path, pushState = true) => {
    loadStartTime = Date.now();
    if (!activeConnection) return;
    // Use the current path if none is specified
    path = path || activeConnection.path;
    // Disable nav buttons while statting
    btnNavBack.disabled = true;
    btnNavForward.disabled = true;
    btnGo.disabled = true;
    // Check if the path exists
    setStatus(`Checking path...`);
    const dataExist = await api.get('files/exists', { path: path });
    // If there was an error
    if (dataExist.error) {
        setStatus(`Error: ${dataExist.error}`, true);
    // If the path doesn't exist
    } else if (!dataExist.exists) {
        setStatus(`Error: Path doesn't exist`, true);
    // Otherwise...
    } else {
        // Update the path bar
        inputNavPath.value = dataExist.path;
        // If the path has changed, push the old path to the back history
        if (pushState && activeConnection.path != path)
            backPaths.push(activeConnection.path);
        // Update the stored current path
        activeConnection.path = dataExist.path;
        // Update display
        document.title = `${activeConnection.name} - ${activeConnection.path}`;
        window.history.replaceState(null, null, `?con=${activeConnectionId}&path=${encodeURIComponent(activeConnection.path)}`);
        // If the path is a directory, load it
        if (dataExist.type == 'd') {
            await loadDirectory(dataExist.path);
        // If the path is a file, load it
        } else {
            await downloadFile(dataExist.path);
            await changePath(`${path}/..`, false);
        }
    }
    // Re-enable nav buttons accordingly
    btnNavBack.disabled = (backPaths.length == 0);
    btnNavForward.disabled = (forwardPaths.length == 0);
    btnGo.disabled = false;
}

/**
 * Loads a directory and populates the file list.
 * @param {string} path The directory path
 */
const loadDirectory = async path => {
    // Hide the file view
    elFiles.style.transition = 'none';
    elFiles.style.pointerEvents = 'none';
    requestAnimationFrame(() => {
        elFiles.style.opacity = 0;
    });
    // Remove all existing file elements
    elFiles.innerHTML = `
        <div class="heading">Folders</div>
        <div id="filesFolders" class="section folders"></div>
        <div class="heading">Files</div>
        <div id="filesFiles" class="section files"></div>
    `;
    const elFilesFolders = $('.folders', elFiles);
    const elFilesFiles = $('.files', elFiles);
    lastSelectedIndex = -1;
    // Disable directory controls
    updateDirControls();
    btnUpload.disabled = true;
    btnDirCreate.disabled = true;
    btnDownload.disabled = true;
    btnShare.disabled = true;
    btnDirSort.disabled = true;
    // Get the directory listing
    setStatus(`Loading directory...`);
    const data = await api.get('directories/list', { path: path });
    // If an error occurred, update the status bar
    // then set the file list to an empty array
    if (data.error) {
        setStatus(`Error: ${data.error}`, true);
        data.list = [];
    }
    // Add the ".." directory
    const list = [{
        name: '..',
        type: 'd',
        longname: '-'
    }, ...data.list];
    // Loop through the list and create file elements
    for (const file of list) {
        const elFile = getFileEntryElement(file, path);
        // Add the file element to the file list
        if (file.type == 'd')
            elFilesFolders.appendChild(elFile);
        else
            elFilesFiles.appendChild(elFile);
    }
    // Sort the file list
    sortFiles();
    // Show the file view
    elFiles.style.transition = '0.15s var(--bezier)';
    requestAnimationFrame(() => {
        elFiles.style.opacity = 1;
        setTimeout(() => {
            elFiles.style.pointerEvents = '';
            elFiles.style.transition = 'none';
        }, 200);
    });
    // Re-enable directory controls accordingly
    fileAccessLock = false;
    if (!data.error) {
        btnUpload.disabled = false;
        btnDirCreate.disabled = false;
        btnDownload.disabled = false;
        btnShare.disabled = false;
        btnDirSort.disabled = false;
        updateDirControls();
        setStatus(`Loaded directory with ${list.length} items in ${Date.now()-loadStartTime}ms`);
    }
}

/**
 * Generates a file list entry element with the data for a given file.
 * @param {object} file A file object returned from the directory list API
 * @param {string} dirPath The path of the directory containing this file
 * @returns {HTMLElement}
 */
const getFileEntryElement = (file, dirPath) => {
    const elFile = document.createElement('button');
    elFile.classList = 'btn fileEntry row';
    // If the file is "hidden", give it the class
    if (file.name != '..' && file.name.substring(0, 1) === '.') {
        elFile.classList.add('hidden');
    }
    // Add data attributes to the file element
    elFile.dataset.path = `${dirPath}/${file.name}`;
    elFile.dataset.type = file.type;
    elFile.dataset.name = file.name;
    elFile.dataset.size = file.size;
    elFile.dataset.date = file.modifyTime;
    // Get icon
    let icon = 'insert_drive_file';
    if (file.type == 'd') icon = 'folder';
    if (file.type == 'l') icon = 'file_present';
    if (file.type == 'b') icon = 'save';
    if (file.type == 'p') icon = 'filter_alt';
    if (file.type == 'c') icon = 'output';
    if (file.type == 's') icon = 'wifi';
    if (file.name == '..') icon = 'drive_folder_upload';
    // Get formatted file info
    const sizeFormatted = (file.size && file.type !== 'd') ? formatSize(file.size) : '-';
    const dateRelative = file.modifyTime ? getRelativeDate(file.modifyTime) : '-';
    const dateAbsolute = file.modifyTime ? dayjs(file.modifyTime).format('MMM D, YYYY, h:mm A') : null;
    const perms = file.longname.split(' ')[0].replace(/\*/g, '');
    const permsNum = (() => {
        let temp;
        let str = '';
        const user = perms.substring(1, 4);
        const group = perms.substring(4, 7);
        const other = perms.substring(7, 10);
        for (const perm of [user, group, other]) {
            temp = 0;
            if (perm.includes('r')) temp += 1;
            if (perm.includes('w')) temp += 2;
            if (perm.includes('x')) temp += 4;
            str += temp;
        }
        return str;
    })();
    // Build the HTML
    let lower = [];
    if (dateRelative !== '-') lower.push(dateRelative);
    if (sizeFormatted !== '-') lower.push(sizeFormatted);
    elFile.innerHTML = /*html*/`
        <div class="icon flex-no-shrink">${icon}</div>
        <div class="nameCont col flex-grow">
            <div class="name"><span title="${file.name}">${file.name}</span></div>
            ${lower.length > 0 ? /*html*/`<div class="lower">${lower.join(' • ')}</div>`:''}
        </div>
        <div class="date flex-no-shrink" ${dateAbsolute ? `title="${dateAbsolute}"`:''}>${dateRelative}</div>
        <div class="size flex-no-shrink">${sizeFormatted}</div>
        <div class="perms flex-no-shrink" title="${permsNum}">${perms}</div>
    `;
    // Handle access
    const accessFile = () => {
        if (fileAccessLock) return;
        // Handle file loading accordingly
        if (file.type !== 'd') {
            const info = getFileExtInfo(file.name, file.size);
            if (info.isViewable) {
                return openFileViewer(elFile.dataset.path);
            } else {
                new PopupBuilder()
                    .setTitle(`File can't be viewed`)
                    .addBodyHTML(`<p>This file can't be viewed in your browser because it's too big or of an unsupported format.</p><p>Download the file to open it.</p>`)
                    .addAction(action => action
                        .setLabel('Download')
                        .setIsPrimary(true)
                        .setClickHandler(() => {
                            downloadFile(elFile.dataset.path);
                        }))
                    .addAction(action => action.setLabel('Cancel'))
                    .show();
            }
        } else {
            // Lock file selection to prevent double-clicking during load
            fileAccessLock = true;
            // Clear forward history and change paths
            forwardPaths = [];
            changePath(elFile.dataset.path);
        }
    };
    // Handle clicks
    let lastClick = 0;
    elFile.addEventListener('click', e => {
        e.stopPropagation();
        if (getIsMobileDevice()) return;
        // If the control key isn't held
        if (!e.ctrlKey) {
            // If this is a double-click
            if ((Date.now()-lastClick) < 300) {
                accessFile();
            }
        }
        // Update our last click time
        lastClick = Date.now();
        // Return if ..
        if (file.name == '..') return;
        // Handle selection
        if (e.shiftKey && lastSelectedIndex >= 0) {
            // Select all files between the last selected file and this one
            // based on this file's index and lastSelectedIndex
            const files = [...$$('#files .fileEntry', elFiles)];
            const start = Math.min(lastSelectedIndex, parseInt(elFile.dataset.index));
            const end = Math.max(lastSelectedIndex, parseInt(elFile.dataset.index));
            for (let j = start; j <= end; j++) {
                const el = files[j];
                selectFile(el.dataset.path, false, false, false);
            }
        } else {
            // Update selection based on shift and ctrl key state
            const state = e.shiftKey || e.ctrlKey;
            selectFile(elFile.dataset.path, !state, state);
        }
    });
    // Handle keypresses
    elFile.addEventListener('keydown', e => {
        // If the enter key is pressed
        if (e.code === 'Enter') {
            accessFile();
        }
        // Focus the next file
        if (e.code == 'ArrowDown') {
            e.preventDefault();
            const next = elFile.nextElementSibling;
            if (next) next.focus();
        }
        // Focus the previous file
        if (e.code == 'ArrowUp') {
            e.preventDefault();
            const prev = elFile.previousElementSibling;
            if (prev) prev.focus();
        }
        // If the escape key is pressed, deselect all files
        if (e.code === 'Escape') {
            deselectAllFiles();
        }
        // Return if ..
        if (file.name == '..') return;
        // If the spacebar is pressed
        if (e.code === 'Space') {
            // Prevent scrolling
            e.preventDefault();
            // Update selection based on ctrl key state
            if (file.name != '..')
                selectFile(elFile.dataset.path, !e.ctrlKey, true);
        }
    });
    // Handle right-clicks
    elFile.addEventListener('contextmenu', e => {
        e.stopPropagation();
        e.preventDefault();
        if (getIsMobileDevice()) return;
        // If the file is already selected, don't change selection
        if (!elFile.classList.contains('selected')) {
            selectFile(elFile.dataset.path, true, true);
        }
        fileContextMenu();
    });
    // Handle mobile touch start
    let timeTouchStart = 0;
    let initialSelectTimeout = null;
    let fileListScrollTopOnStart = 0;
    elFile.addEventListener('touchstart', e => {
        if (!getIsMobileDevice()) return;
        timeTouchStart = Date.now();
        fileListScrollTopOnStart = elFiles.scrollTop;
        if (!checkIsSelecting()) {
            initialSelectTimeout = setTimeout(() => {
                if ((Date.now()-timeTouchStart) > 1000) return;
                selectFile(elFile.dataset.path, true, false);
                if (navigator.vibrate) navigator.vibrate(2);
            }, 400);
        }
    });
    // Handle mobile touch end
    elFile.addEventListener('touchend', e => {
        if (!getIsMobileDevice()) return;
        clearTimeout(initialSelectTimeout);
        if ((Date.now()-timeTouchStart) > 380) return;
        if (elFiles.scrollTop != fileListScrollTopOnStart) return;
        if (checkIsSelecting()) {
            selectFile(elFile.dataset.path, false, true);
        } else {
            accessFile();
        }
    });
    // Handle mobile touch move
    elFile.addEventListener('touchmove', e => {
        if (!getIsMobileDevice()) return;
        clearTimeout(initialSelectTimeout);
        timeTouchStart = 0;
    });
    return elFile;
}

/**
 * Displays a context menu with actions for the selected file(s).
 * @param {HTMLElement} elDisplay An HTML element to display the menu relative to
 */
const fileContextMenu = (elDisplay = null) => {
    const allVisibleFiles = [...$$('#files .fileEntry:not(.hidden)', elFiles)];
    if (showHidden)
        allVisibleFiles.push(...[...$$('#files .fileEntry.hidden', elFiles)]);
    const selectedFiles = [...getSelectedFiles()];
    // We have to delay button clicks to allow time for
    // the context menu to lose focus trap
    const clickButton = btn => setTimeout(() => btn.click(), 100);
    // Selection status shortcuts
    const isNoneSelected = selectedFiles.length == 0;
    const isSomeSelected = selectedFiles.length > 0;
    const isSingleSelected = selectedFiles.length == 1;
    const isMultiSelected = selectedFiles.length > 1;
    const isAllSelected = selectedFiles.length == allVisibleFiles.length-1;
    // Build the menu
    const menu = new ContextMenuBuilder();
    if (isNoneSelected) menu.addItem(item => {
        item.setIcon($('.icon', btnUpload).innerText)
            .setLabel('Upload files...')
            .setClickHandler(() => clickButton(btnUpload))
        btnUpload.disabled ? item.disable() : item.enable();
        return item;
    });
    if (isNoneSelected) menu.addItem(item => {
        item.setIcon($('.icon', btnDirCreate).innerText)
            .setLabel('New folder...')
            .setClickHandler(() => clickButton(btnDirCreate))
        btnDirCreate.disabled ? item.disable() : item.enable();
        return item;
    });
    if (isNoneSelected) menu.addSeparator();
    if (!btnSelectionCut.disabled) menu.addItem(item => {
        item.setIcon($('.icon', btnSelectionCut).innerText)
            .setLabel(`Cut`)
            .setClickHandler(() => clickButton(btnSelectionCut))
        return item;
    });
    if (!btnSelectionCopy.disabled) menu.addItem(item => {
        item.setIcon($('.icon', btnSelectionCopy).innerText)
            .setLabel(`Copy`)
            .setClickHandler(() => clickButton(btnSelectionCopy))
        return item;
    });
    if (isNoneSelected) menu.addItem(item => {
        item.setIcon($('.icon', btnSelectionPaste).innerText)
            .setLabel(`Paste`)
            .setClickHandler(() => clickButton(btnSelectionPaste))
        btnSelectionPaste.disabled ? item.disable() : item.enable();
        return item;
    });
    if (isSomeSelected) menu.addSeparator();
    if (!btnRename.disabled) menu.addItem(item => {
        item.setIcon($('.icon', btnRename).innerText)
            .setLabel('Rename...')
            .setClickHandler(() => clickButton(btnRename))
        return item;
    });
    if (!btnSelectionMoveTo.disabled) menu.addItem(item => {
        item.setIcon($('.icon', btnSelectionMoveTo).innerText)
            .setLabel(`Move to...`)
            .setClickHandler(() => clickButton(btnSelectionMoveTo))
        return item;
    });
    if (!btnSelectionCopyTo.disabled) menu.addItem(item => {
        item.setIcon($('.icon', btnSelectionCopyTo).innerText)
            .setLabel(`Copy to...`)
            .setClickHandler(() => clickButton(btnSelectionCopyTo))
        return item;
    });
    if (!btnSelectionDelete.disabled) menu.addItem(item => {
        item.setIcon($('.icon', btnSelectionDelete).innerText)
            .setLabel(`Delete...`)
            .setClickHandler(() => clickButton(btnSelectionDelete))
            .setIsDanger(true)
        return item;
    });
    menu.addSeparator();
    menu.addItem(item => {
        item.setIcon('download')
            .setLabel(`Download`)
            .setClickHandler(() => clickButton(btnDownload))
        btnDownload.disabled ? item.disable() : item.enable();
        return item;
    });
    if (!isLocalhost) menu.addItem(item => {
        item.setIcon('share')
            .setLabel(`Copy download link...`)
            .setClickHandler(() => clickButton(btnShare))
        btnDownload.disabled ? item.disable() : item.enable();
        return item;
    });
    if (!isMultiSelected) menu.addSeparator();
    if (!isMultiSelected) menu.addItem(item => {
        item.setIcon('conversion_path')
            .setLabel('Copy path')
            .setClickHandler(() => {
                const path = isNoneSelected ? activeConnection.path : selectedFiles[0].dataset.path;
                navigator.clipboard.writeText(path);
                setStatus(`Copied path to clipboard`);
            })
        return item;
    });
    if (allVisibleFiles.length > 1)
        menu.addSeparator();
    if (!isAllSelected) menu.addItem(item => item
        .setIcon('select_all')
        .setLabel('Select all')
        .setTooltip('Ctrl + A')
        .setClickHandler(selectAllFiles))
    if (isSomeSelected) menu.addItem(item => item
        .setIcon('select')
        .setLabel('Deselect all')
        .setTooltip('Ctrl + Shift + A')
        .setClickHandler(deselectAllFiles))
    if (isSomeSelected && !isAllSelected) menu.addItem(item => item
        .setIcon('move_selection_up')
        .setLabel('Invert selection')
        .setTooltip('Ctrl + Alt + A')
        .setClickHandler(invertFileSelection))
    if (elDisplay) {
        const rect = elDisplay.getBoundingClientRect();
        menu.showAtCoords(rect.left, rect.bottom-5);
    } else {
        menu.showAtCursor();
    }
}

/**
 * Sorts the current file list using `sortType` and `sortDesc`.
 */
const sortFiles = () => {
    // Define sorting functions
    const sortFuncs = {
        name: (a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }),
        size: (a, b) => a.size - b.size,
        date: (a, b) => a.date - b.date
    };
    // Loop through file sections
    const sections = [...$$('.section', elFiles)];
    let i = 0;
    for (const section of sections) {
        const files = [...$$('#files .fileEntry', section)];
        // Sort files
        files.sort((a, b) => {
            if (a.dataset.name == '..') return -1;
            if (b.dataset.name == '..') return 1;
            const aData = {
                name: a.dataset.name,
                size: parseInt(a.dataset.size),
                date: parseInt(a.dataset.date)
            };
            const bData = {
                name: b.dataset.name,
                size: parseInt(b.dataset.size),
                date: parseInt(b.dataset.date)
            };
            const sortFunc = sortFuncs[sortType];
            return sortFunc(aData, bData) * (sortDesc ? -1 : 1);
        });
        // Append files to the file list
        for (const file of files) {
            file.dataset.index = i;
            section.appendChild(file);
            i++;
        }
    }
}

/**
 * Changes the file sort type and re-sorts the file list.
 * @param {sortType} type The new sort type
 */
const changeFileSortType = type => {
    sortType = type;
    window.localStorage.setItem('sortType', sortType);
    sortFiles();
}

/**
 * Changes the file sort direction and re-sorts the file list.
 * @param {sortDesc} descending
 */
const changeFileSortDirection = descending => {
    sortDesc = descending;
    window.localStorage.setItem('sortDesc', sortDesc);
    sortFiles();
}

/**
 * Changes the file view mode and updates the file list.
 * @param {viewMode} type The new view mode
 */
const changeFileViewMode = type => {
    if (type == 'list' && window.innerWidth < forceTileViewWidth) {
        return new PopupBuilder()
            .setTitle(`Can't switch to list view`)
            .addBodyHTML(`<p>Your screen is too narrow to switch to list view! Rotate your device or move to a larger screen, then try again.</p>`)
            .addAction(action => action.setLabel('Okay').setIsPrimary(true))
            .show();
    }
    viewMode = type;
    window.localStorage.setItem('viewMode', viewMode);
    elFiles.classList.remove('list', 'tiles');
    elFiles.classList.add(viewMode);
    elFileColHeadings.classList.toggle('tiles', type == 'tiles');
}

/** Toggles the visibility of hidden files. */
const toggleHiddenFileVisibility = () => {
    showHidden = !showHidden;
    window.localStorage.setItem('showHidden', showHidden);
    elFiles.classList.toggle('showHidden', showHidden);
}

/**
 * Opens a file preview/editor tab/window.
 * @param {string} path The file path.
 */
const openFileViewer = path => {
    const url = `/file.html?con=${activeConnectionId}&path=${encodeURIComponent(path)}`;
    const isStandalone =
           window.matchMedia('(display-mode: standalone)').matches
        || window.matchMedia('(display-mode: minimal-ui)').matches;
    if (!isStandalone) {
        // Open in new tab
        window.open(url, '_blank');
    } else {
        // Set size
        const viewerWidth = parseInt(window.localStorage.getItem('viewerWidth')) || window.innerWidth;
        const viewerHeight = parseInt(window.localStorage.getItem('viewerHeight')) || window.innerHeight;
        const coords = {
            // Center the new window on top of this one
            x: window.screenX + (window.innerWidth - viewerWidth)/2,
            y: window.screenY + (window.innerHeight - viewerHeight)/2,
            w: viewerWidth,
            h: viewerHeight
        };
        // Open window
        window.open(url, path, `width=${coords.w},height=${coords.h},left=${coords.x},top=${coords.y}`);
    }
}

/**
 * Resolves with a download URL for a zip file containing all of the files and directories specified, or `false` if an error occurred.
 * @param {string[]} paths An array of file and/or directory paths
 * @param {string} rootPath The directory path to start at inside the zip file - leave undefined to use `'/'`
 * @returns {Promise<string|boolean>}
 */
const getZipDownloadUrl = async(paths, rootPath = '/') => {
    const pathsJson = JSON.stringify(paths);
    if ((pathsJson.length+rootPath.length) > 1900) {
        return setStatus(`Error: Too many selected paths for zip download`, true);
    }
    setStatus(`Getting zip file download URL...`);
    const res = await api.get('files/get/multi/url', {
        paths: pathsJson,
        rootPath: rootPath
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
 * Starts a zip file download for all of the paths specified.
 * @param {string[]} paths An array of file and/or directory paths
 * @param {string} [rootPath='/'] The directory path to start at inside the zip file
 */
const downloadZip = async(paths, rootPath = '/') => {
    const url = await getZipDownloadUrl(paths, rootPath);
    if (url) {
        downloadUrl(url);
        setStatus(`Zip file download started`);
    }
}

/**
 * Updates the disabled/enabled state of all control buttons depending on the currently selected file entries.
 */
const updateDirControls = () => {
    const selectedFiles = $$('.selected', elFiles);
    btnSelectionCut.disabled = true;
    btnSelectionCopy.disabled = true;
    btnSelectionPaste.disabled = true;
    btnRename.disabled = true;
    btnSelectionMoveTo.disabled = true;
    btnSelectionCopyTo.disabled = true;
    btnSelectionDelete.disabled = true;
    btnDeselectAll.style.display = 'none';
    // When no files are selected
    if (selectedFiles.length == 0) {
        btnDirMenu.classList.remove('info');
    // When files are selected
    } else {
        btnDirMenu.classList.add('info');
        // When a single file is selected
        if (selectedFiles.length == 1) {
            btnRename.disabled = false;
        }
        btnSelectionCut.disabled = false;
        btnSelectionCopy.disabled = false;
        btnSelectionMoveTo.disabled = false;
        btnSelectionCopyTo.disabled = false;
        btnSelectionDelete.disabled = false;
        btnDeselectAll.style.display = '';
    }
    // When there are files in the clipboard
    if (selectionClipboard.length > 0) {
        btnSelectionPaste.disabled = false;
    }
}

/**
 * An array of all selected file elements.
 * @returns {HTMLElement[]}
 */
const getSelectedFiles = () => [...$$('.selected', elFiles)];

/**
 * Updates the selected state of the file element with the specified path.
 * @param {string} path The path of the file to select in the list
 * @param {boolean} [deselectOthers] If `true`, other files will be deselected - defaults to `true`
 * @param {boolean} [toggle] If `true`, toggle the selected state of this file - defaults to `false`
 * @param {boolean} [focus] If `true`, focus this file element in the list - defaults to `false`
 */
const selectFile = (path, deselectOthers = true, toggle = false, focus = false) => {
    const el = $(`.fileEntry[data-path="${path}"]`, elFiles);
    if (!el) return;
    if (el.dataset.name == '..') return;
    const isSelected = el.classList.contains('selected');
    if (deselectOthers) deselectAllFiles();
    if (toggle)
        el.classList.toggle('selected', !isSelected);
    else
        el.classList.add('selected');
    if (focus) el.focus();
    deselectHiddenFiles();
    lastSelectedIndex = parseInt(el.dataset.index);
    updateDirControls();
}

/**
 * Selects all files in the file list, excluding hidden ones if they aren't visible.
 */
const selectAllFiles = () => {
    const files = [...$$('.fileEntry', elFiles)];
    files.shift();
    for (const el of files) {
        el.classList.add('selected');
    }
    deselectHiddenFiles();
    lastSelectedIndex = parseInt($('.fileEntry.selected:last-child', elFiles).dataset.index || -1);
    updateDirControls();
}

/**
 * Deselects all files in the file list.
 */
const deselectAllFiles = () => {
    const selected = getSelectedFiles();
    for (const el of selected) {
        el.classList.remove('selected');
    }
    lastSelectedIndex = -1;
    updateDirControls();
}

/**
 * Deselects all invisible files in the file list. Nothing will happen if hidden files are visible.
 */
const deselectHiddenFiles = () => {
    if (showHidden) return;
    const hidden = [...$$('.hidden', elFiles)];
    for (const el of hidden) {
        el.classList.remove('selected');
    }
    updateDirControls();
}

/**
 * Inverts the current file selection, only including visible files.
 */
const invertFileSelection = () => {
    const files = [...$$('#files .fileEntry', elFiles)];
    files.shift();
    for (const el of files) {
        el.classList.toggle('selected');
    }
    lastSelectedIndex = parseInt($('#files .fileEntry:last-child', elFiles).dataset.index) || -1;
    deselectHiddenFiles();
    updateDirControls();
}

/**
 * Returns `true` if there are currently files selected, `false` otherwise.
 * @returns {boolean}
 */
const checkIsSelecting = () => {
    const selected = getSelectedFiles();
    return selected.length > 0;
}

/**
 * Opens a dialog prompting the user to create a directory.
 */
const createDirectoryDialog = () => {
    const el = document.createElement('div');
    el.innerHTML = /*html*/`
        <div style="width: 300px; max-width: 100%">
            <input type="text" class="textbox" id="inputDirName" placeholder="Folder name">
        </div>
    `;
    const inputDirName = $('#inputDirName', el);
    const popup = new PopupBuilder()
        .setTitle('New folder')
        .addBody(el)
        .addAction(action => action
            .setIsPrimary(true)
            .setLabel('Create')
            .setClickHandler(async() => {
                const name = inputDirName.value;
                if (!name) return;
                const path = `${activeConnection.path}/${name}`;
                const data = await api.post('directories/create', { path: path });
                if (data.error) {
                    setStatus(`Error: ${data.error}`, true);
                } else {
                    await changePath();
                    selectFile(data.path, true, false, true);
                }
            }))
        .addAction(action => action.setLabel('Cancel'))
        .show();
    inputDirName.focus();
    inputDirName.addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            $('.btn:first-of-type', popup.el).click();
        }
    });
}

/**
 * Opens a dialog prompting the user to rename the file with the specified path.
 * @param {string} path The file path
 */
const renameFileDialog = async path => {
    const el = document.createElement('div');
    const currentName = path.split('/').pop();
    el.innerHTML = /*html*/`
        <div style="width: 400px; max-width: 100%">
            <input type="text" class="textbox" id="inputFileName" placeholder="${currentName}" value="${currentName}">
        </div>
    `;
    const input = $('#inputFileName', el);
    const popup = new PopupBuilder()
        .setTitle(`Rename file`)
        .addBody(el)
        .addAction(action => action
            .setIsPrimary(true)
            .setLabel('Rename')
            .setClickHandler(async() => {
                const name = input.value;
                if (!name) return;
                const pathOld = path;
                const pathNew = pathOld.split('/').slice(0, -1).join('/') + '/' + name;
                // Check if the new path exists
                const resExistsCheck = await api.get('files/exists', { path: pathNew });
                if (resExistsCheck.exists) {
                    const replaceStatus = await replaceDialog(pathNew);
                    if (replaceStatus == 'skip' || replaceStatus == 'skipAll')
                        return setStatus(`Rename cancelled`);
                    await deleteFile(pathNew);
                }
                const data = await api.put('files/move', {
                    pathOld, pathNew
                });
                if (data.error) {
                    setStatus(`Error: ${data.error}`, true);
                } else {
                    const pathNewDir = data.pathNew.split('/').slice(0, -1).join('/');
                    await changePath(pathNewDir);
                    selectFile(data.pathNew, true, false, true);
                }
            }))
        .addAction(action => action.setLabel('Cancel'))
        .show();
    input.focus();
    input.select();
    input.addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            $('.btn:first-of-type', popup.el).click();
        }
    });
}

/**
 * Opens a dialog prompting the user to select a directory with an interactive browser.
 * @param {string} [startPath] The directory to start in
 * @param {string} [title] The popup title
 * @param {string} [actionLabel] The label of the confirm button
 * @returns {Promise<string|null>} A promise resolving to the selected directory path, or `null` if cancelled
 */
const selectDirDialog = async(startPath = activeConnection.path, title = 'Select folder', actionLabel = 'Select') => new Promise(resolve => {
    const el = document.createElement('div');
    el.innerHTML = /*html*/`
        <div class="moveFilesPicker col gap-10" style="width: 500px; max-width: 100%">
            <div class="row gap-10">
                <input type="text" class="textbox" id="inputDirPath" placeholder="${startPath}">
                <button class="btn secondary iconOnly go">
                    <div class="icon">keyboard_return</div>
                </button>
            </div>
            <div class="folders col"></div>
        </div>
    `;
    const input = $('#inputDirPath', el);
    const btnGo = $('.btn.go', el);
    const elFolders = $('.folders', el);
    const loadFolders = async dir => {
        elFolders.innerHTML = '';
        const data = await api.get('directories/list', {
            path: dir, dirsOnly: true
        });
        const subDirs = data.list || [];
        subDirs.sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
        if (dir != '/') subDirs.unshift({ name: '..' });
        for (const subDir of subDirs) {
            const elDir = document.createElement('button');
            elDir.classList = 'btn fileEntry row gap-10';
            if (subDir.name != '..' && subDir.name.substring(0, 1) === '.')
                elDir.classList.add('hidden');
            let subDirPath = path = `${dir}/${subDir.name}`;
            elDir.innerHTML = /*html*/`
                <div class="icon flex-no-shrink">folder</div>
                <div class="nameCont flex-grow">
                    <div class="name"><span title="${subDir.name}">${subDir.name}</span></div>
                </div>
            `;
            elDir.addEventListener('click', () => {
                loadFolders(subDirPath);
            });
            elFolders.appendChild(elDir);
        }
        if (data.path) input.value = data.path;
    };
    btnGo.addEventListener('click', () => loadFolders(input.value || startPath || '/'));
    btnGo.click();
    input.addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            btnGo.click();
        }
    });
    new PopupBuilder()
        .setTitle(title)
        .addBody(el)
        .addAction(action => action
            .setIsPrimary(true)
            .setLabel(actionLabel)
            .setClickHandler(() => resolve(input.value)))
        .addAction(action => action.setLabel('Cancel'))
        .setOnHide(() => resolve(null))
        .show();
});

/**
 * Moves files from their original directories into a single new directory while keeping their names.
 * @param {string} newDirPath The new directory
 * @param {string[]} filePaths An array of file paths to move
 * @returns {Promise<string[]|null>} An array of new paths of the files successfully moved, or `null` if no files were moved
 */
const moveFiles = async(newDirPath, filePaths) => {
    // Loop through selected files
    const newPaths = [];
    let i = 0;
    let replaceStatus = null;
    for (const pathOld of filePaths) {
        const name = pathOld.split('/').pop();
        const pathNew = `${newDirPath}/${name}`;
        if (pathOld == pathNew) continue;
        setStatus(`Moving file: ${pathOld}`, false, Math.round((i/filePaths.length)*100));
        i++;
        // Check if the new path exists
        // If it does, prompt the user to replace it
        const resExistsCheck = await api.get('files/exists', { path: pathNew });
        if (resExistsCheck.exists) {
            if (replaceStatus != 'replaceAll') {
                if (replaceStatus != 'skipAll') {
                    replaceStatus = await replaceDialog(pathNew);
                }
                if (replaceStatus == 'skip' || replaceStatus == 'skipAll') {
                    setStatus(`File move skipped`);
                    continue;
                }
            }
            await deleteFile(pathNew);
        }
        const data = await api.put('files/move', {
            pathOld, pathNew
        });
        if (data.error) {
            setStatus(`Error: ${data.error}`, true);
            break;
        }
        const el = $(`#files .fileEntry[data-path="${pathOld}"]`, elFiles);
        if (el) el.remove();
        newPaths.push(data.pathNew);
    }
    if (newPaths.length > 0) {
        setStatus(`Moved ${newPaths.length} file(s) to ${newDirPath}`);
        return newPaths;
    }
    return null;
}

/**
 * Copies files into the provided directory.
 * @param {string} newDirPath The target directory
 * @param {string[]} filePaths An array of file paths to copy
 * @returns {Promise<string[]|null>} An array of new paths of the files successfully copied, or `null` if no files were copied
 */
const copyFiles = async(newDirPath, filePaths) => {
    // Loop through selected files
    const newPaths = [];
    let i = 0;
    let replaceStatus = null;
    for (const pathSource of filePaths) {
        const name = pathSource.split('/').pop();
        const pathDest = `${newDirPath}/${name}`;
        if (pathSource == pathDest) continue;
        setStatus(`Copying file: ${pathSource}`, false, Math.round((i/filePaths.length)*100));
        i++;
        // Check if the new path exists
        // If it does, prompt the user to replace it
        const resExistsCheck = await api.get('files/exists', { path: pathDest });
        if (resExistsCheck.exists) {
            if (replaceStatus != 'replaceAll') {
                if (replaceStatus != 'skipAll') {
                    replaceStatus = await replaceDialog(pathDest);
                }
                if (replaceStatus == 'skip' || replaceStatus == 'skipAll') {
                    setStatus(`File copy skipped`);
                    continue;
                }
            }
            await deleteFile(pathDest);
        }
        const data = await api.put('files/copy', {
            pathSrc: pathSource, pathDest: pathDest
        });
        if (data.error) {
            setStatus(`Error: ${data.error}`, true);
            return false;
        }
        newPaths.push(data.pathDest);
    }
    if (newPaths.length > 0) {
        setStatus(`Copied ${newPaths.length} file(s) to ${newDirPath}`);
        return newPaths;
    }
    return false;
}

/**
 * Opens a dialog prompting the user to select a directory to transfer the selected files to.
 * @param {boolean} copy If `true`, copy the files instead of moving them
 * @returns {Promise<string[]|null>} An array of new file paths, or `null` if no files were transferred
 */
const moveFilesDialog = async(copy = false) => {
    const selectedPaths = [...getSelectedFiles()].map(el => el.dataset.path);
    // Prompt the user to select a directory
    const newDirPath = await selectDirDialog(undefined, `${copy ? 'Copy':'Move'} ${selectedPaths.length > 1 ? `${selectedPaths.length} files`:'file'}`, `${copy ? 'Copy':'Move'} here`);
    if (!newDirPath) return null;
    // Move or copy the files
    if (copy)
        return copyFiles(newDirPath, selectedPaths);
    else
        return moveFiles(newDirPath, selectedPaths);
}

/**
 * Prompts the user if they want to skip or replace the current file in the current transfer process, with the additional option of doing this for the all remaining conflicts.
 * @param {string} fileName The file's name or path to display to the user
 * @returns {Promise<'skip'|'skipAll'|'replace'|'replaceAll'>} One of 4 states representing the user's choice: `skip`, `skipAll`, `replace`, `replaceAll`
 */
const replaceDialog = fileName => new Promise(resolve => {
    const el = document.createElement('div');
    el.innerHTML = `
        <p><b>${fileName}</b> already exists. Do you want to replace it?</p>
        <label class="selectOption">
            <input type="checkbox">
            Do this for all remaining conflicts
        </label>
    `;
    const checkbox = $('input', el);
    new PopupBuilder()
        .setTitle(`File exists`)
        .addBody(el)
        .addAction(action => action
            .setIsPrimary(true)
            .setLabel('Replace')
            .setClickHandler(() => resolve(checkbox.checked ? 'replaceAll':'replace')))
        .addAction(action => action
            .setLabel('Skip')
            .setClickHandler(() => resolve(checkbox.checked ? 'skipAll':'skip')))
        .show();
});

/**
 * Uploads input files to the active server.
 * @param {FileSystemHandle[]} inputFiles The input files
 */
const uploadFiles = async inputFiles => {
    if (isUploading) return new PopupBuilder()
        .setTitle('Upload in progress')
        .addBodyHTML('<p>An upload is already in progress. Wait for it to finish before uploading more files.</p>')
        .addAction(action => action.setIsPrimary(true).setLabel('Okay'))
        .show();
    isUploading = true;
    let isCancelled = false;
    let replaceStatus = null;
    let dirPath = activeConnection.path;
    // Handle status and progress bar
    let lastStatusSet = 0;
    const setUploadStatus = (text, progress = 0) => {
        if ((Date.now()-lastStatusSet) < 500) return;
        setStatus(`<span><a href="#" class="text-danger" style="text-decoration: none">Cancel</a> | ${text}</span>`, false, progress);
        const anchor = $('a', elStatusBar);
        anchor.addEventListener('click', e => {
            isCancelled = true;
        });
        lastStatusSet = Date.now();
    };
    // Sort input files
    inputFiles = [...inputFiles];
    inputFiles.sort((a, b) => a.name.localeCompare(b.name));
    // Loop through selected files
    let startTime = Date.now();
    let totalBytesUploaded = 0;
    const paths = [];
    for (const file of inputFiles) {
        if (isCancelled) break;
        setUploadStatus(`Uploading file: ${file.name}`);
        // Check if the path exists
        let path = `${dirPath}/${file.name}`;
        const resExistenceCheck = await api.get('files/exists', { path: path });
        path = resExistenceCheck.path;
        // If the file exists, prompt the user to replace it
        if (resExistenceCheck.exists) {
            if (replaceStatus != 'replaceAll') {
                if (replaceStatus != 'skipAll') {
                    replaceStatus = await replaceDialog(path);
                }
                if (replaceStatus == 'skip' || replaceStatus == 'skipAll') {
                    setStatus(`Upload skipped`);
                    continue;
                }
            }
            const resDelete = await deleteFile(path);
            if (resDelete.error) return;
        }
        // Make a promise to upload the file
        await new Promise(async(resolve, reject) => {
            let isUploadComplete = false;
            // Get socket key
            const resSocketKey = await api.get('key');
            const key = resSocketKey.key;
            // Connect to the file append websocket
            const url = `${wsProtocol}://${apiHost}/api/sftp/files/append?path=${encodeURIComponent(path)}&key=${key}`;
            const ws = new WebSocket(url);
            // Resolve with error if the websocket closes or errors
            // before the upload is complete
            ws.addEventListener('close', () => {
                if (!isUploadComplete) {
                    isUploading = false;
                    setStatus(`Error: Websocket unexpectedly closed`, true)
                    resolve('unexpectedClose');
                }
            });
            ws.addEventListener('error', (e) => {
                if (!isUploadComplete) {
                    isUploading = false;
                    setStatus(`Error: Websocket error`, true)
                    resolve('wsError');
                }
            });
            // Handle messages
            const messageHandlers = [];
            ws.addEventListener('message', e => {
                const data = JSON.parse(e.data);
                console.log(`Message from upload websocket:`, data);
                if (!data.success)  {
                    isUploading = false;
                    setStatus(`Error: ${data.error}`, true)
                    resolve('error');
                }
                const handler = messageHandlers.shift();
                if (handler) handler(data.success || false);
            });
            // Wait for the websocket to open
            await new Promise(resolve2 => {
                messageHandlers.push(resolve2);
            });
            console.log(`Opened websocket: ${url}`);
            // Upload the file in chunks
            const fileSize = file.size;
            const bytesPerChunk = 1024*1024*1;
            const chunkCount = Math.ceil(file.size / bytesPerChunk);
            for (let i = 0; i < chunkCount; i++) {
                if (isCancelled) break;
                const startByte = i * bytesPerChunk;
                const endByte = Math.min(file.size, (i+1) * bytesPerChunk);
                const thisChunkSize = endByte - startByte;
                const chunk = file.slice(startByte, endByte);
                // Upload the chunk
                const res = await new Promise(resolve2 => {
                    // Resolve when the chunk is uploaded
                    // and server sends a success message
                    messageHandlers.push(resolve2);
                    ws.send(chunk);
                });
                if (!res) break;
                // Update status with progress
                totalBytesUploaded += thisChunkSize;
                const bytesUploaded = Math.min((i+1)*bytesPerChunk, fileSize);
                const bytesPerSecond = totalBytesUploaded / ((Date.now()-startTime)/1000);
                const percentUploaded = Math.round((bytesUploaded/fileSize)*100);
                setUploadStatus(`Uploading file: ${file.name} | ${formatSize(bytesUploaded)} of ${formatSize(fileSize)} (${formatSize(bytesPerSecond)}/s)`, percentUploaded);
            }
            isUploadComplete = true;
            ws.close();
            resolve('done');
        });
        if (!isUploading) return;
        // If the upload was cancelled, delete the file
        if (isCancelled) {
            await deleteFile(path);
            setStatus(`Upload cancelled`);
            break;
        }
        // Add the path to the list of uploaded files
        paths.push(path);
        // Add the file to the file list
        if (dirPath == activeConnection.path) {
            const elExisting = $(`.fileEntry[data-path="${path}"]`, elFiles);
            if (elExisting) elExisting.remove();
            const elFile = getFileEntryElement({
                name: file.name,
                type: '-',
                size: file.size,
                modifyTime: Date.now(),
                longname: '-'
            }, dirPath);
            $('.section.files', elFiles).appendChild(elFile);
            sortFiles();
        }
    }
    isUploading = false;
    if (paths.length == 0) return;
    // Select all new files
    for (const path of paths) {
        selectFile(path, false, false, true);
    }
    setStatus(`Uploaded ${paths.length} file(s)`);
}

/**
 * Opens a system file picker and uploads the selected files to the active server.
 */
const uploadFilesPrompt = async() => {
    // Prompt user to select files
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    input.click();
    // When files are selected
    input.addEventListener('change', () => {
        uploadFiles(input.files);
    });
}

/**
 * Deletes a file from the active server.
 * @param {string} path The file path
 * @param {boolean} refresh If `true`, refresh the file list after deleting the file - defaults to `true`
 * @returns {Promise<Object>} The API response object
 */
const deleteFile = async(path) => {
    const data = await api.delete('files/delete', { path: path });
    if (data.error) {
        setStatus(`Error: ${data.error}`, true);
    } else {
        const elFile = $(`.fileEntry[data-path="${path}"]`, elFiles);
        if (elFile) elFile.remove();
    }
    return data;
}

/**
 * Deletes a directory from the active server.
 * @param {string} path The directory path
 * @param {boolean} refresh If `true`, refresh the file list after deleting the directory - defaults to `true`
 * @returns {Promise<Object>} The API response object
 */
const deleteDirectory = async(path) => {
    const data = await api.delete('directories/delete', { path: path });
    if (data.error) {
        setStatus(`Error: ${data.error}`, true);
    } else {
        const elFile = $(`.fileEntry[data-path="${path}"]`, elFiles);
        if (elFile) elFile.remove();
    }
    return data;
}

/**
 * Shows a context menu containing a set of navigable file paths.
 * @param {Event} e The `ContextMenu` event
 * @param {HTMLElement} btn The button that was clicked
 * @param {string[]} paths An array of paths to show in the menu
 * @param {ContextMenuBuilder} menu An existing menu object to add items to
 */
const historyContextMenu = (e, btn, paths, menu = new ContextMenuBuilder()) => {
    if (btn.disabled) return;
    e.preventDefault();
    paths = JSON.parse(JSON.stringify(paths)).reverse();
    for (let i = 0; i < 10; i++) {
        let path = paths[i];
        if (!path) break;
        let split = path.split('/');
        let base = split.pop();
        let dir = `/${split.join('/')}/`.replace(/\/\//g, '/');
        menu.addItem(item => {
            const html = /*html*/`
                <span style="color: var(--f3)">${escapeHTML(dir)}<span style="color: var(--f1)">${escapeHTML(base)}</span></span>
            `;
            item.elLabel.innerHTML = html;
            const span = $('span', item.elLabel);
            span.title = html;
            item.setClickHandler(() => {
                changePath(path, false);
            });
            return item;
        });
    }
    menu.el.style.maxWidth = '100%';
    menu.setIconVisibility(false);
    const rect = btn.getBoundingClientRect();
    menu.showAtCoords(rect.left, rect.bottom-5);
}

btnConnections.addEventListener('click', () => {
    const menu = new ContextMenuBuilder();
    for (const id in connections) {
        const connection = connections[id];
        menu.addItem(option => option
            .setLabel(connection.name)
            .setIcon('cloud')
            .setTooltip(`Click to connect to ${connection.name}<br><small>${connection.username}@${connection.host}:${connection.port}<br>${connection.path}</small>`)
            .setClickHandler(() => {
                setActiveConnection(id);
            }));
    };
    menu.addSeparator();
    menu.addItem(option => option
        .setLabel('Manage connections...')
        .setIcon('smb_share')
        .setClickHandler(connectionManagerDialog));
    menu.addItem(option => option
        .setLabel('New connection...')
        .setIcon('library_add')
        .setClickHandler(addNewConnectionDialog));
    menu.addSeparator().addItem(item => item
        .setIcon('code')
        .setLabel('SFTP Browser GitHub')
        .setClickHandler(() => {
            window.open('https://github.com/CyberGen49/sftp-browser');
        }));
    const rect = btnConnections.getBoundingClientRect();
    menu.showAtCoords(rect.left, rect.bottom-5);
});

btnNavBack.addEventListener('click', () => {
    if (backPaths.length > 0) {
        forwardPaths.push(activeConnection.path);
        changePath(backPaths.pop(), false);
    }
});
btnNavForward.addEventListener('click', () => {
    if (forwardPaths.length > 0) {
        backPaths.push(activeConnection.path);
        changePath(forwardPaths.pop(), false);
    }
});

btnNavBack.addEventListener('contextmenu', (e) => {
    historyContextMenu(e, btnNavBack, backPaths);
});
btnNavForward.addEventListener('contextmenu', (e) => {
    historyContextMenu(e, btnNavForward, forwardPaths);
});

inputNavPath.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
        btnGo.click();
    }
});
btnGo.addEventListener('click', () => {
    changePath(inputNavPath.value || '/');
});

btnPathPopup.addEventListener('click', () => {
    const menu = new ContextMenuBuilder()
        .addItem(item => item
            .setIcon('pin_drop')
            .setLabel('Go to path...')
            .setClickHandler(() => {
                const popup = new PopupBuilder()
                    .setTitle('Go to path')
                    .addAction(action => action
                        .setIsPrimary(true)
                        .setLabel('Go')
                        .setClickHandler(() => {
                            const path = $('#inputGoToPath', popup.el).value || activeConnection.path;
                            if (path == activeConnection.path) return;
                            changePath(path);
                            popup.hide();
                        }))
                    .addAction(action => action.setLabel('Cancel'))
                const elBody = $('.body', popup.el);
                elBody.innerHTML = /*html*/`
                    <div style="width: 400px; max-width: 100%">
                        <input type="text" class="textbox" id="inputGoToPath" placeholder="${activeConnection.path}" value="${activeConnection.path}">
                    </div>
                `;
                const input = $('#inputGoToPath', elBody);
                input.addEventListener('keydown', e => {
                    if (e.key === 'Enter') {
                        $('.btn:first-of-type', popup.el).click();
                    }
                });
                popup.show();
                setTimeout(() => {
                    input.focus();
                    input.select();
                }, 100);
            }));
    const pathSplit = activeConnection.path.split('/');
    pathSplit.pop();
    if (pathSplit.length > 0) {
        menu.addSeparator();
        let path = '';
        for (const node of pathSplit) {
            path += `/${node}`;
            menu.addItem(item => item
                .setIcon('folder_open')
                .setLabel(node || '/')
                .setClickHandler(() => {
                    changePath(path);
                }));
        }
    }
    const rect = btnPathPopup.getBoundingClientRect();
    menu.showAtCoords(rect.right, rect.bottom-5);
});

btnDirMenu.addEventListener('click', () => {
    fileContextMenu(btnDirMenu);
});

btnDeselectAll.addEventListener('click', deselectAllFiles);

btnUpload.addEventListener('click', uploadFilesPrompt);

btnDirCreate.addEventListener('click', createDirectoryDialog);

btnRename.addEventListener('click', () => {
    renameFileDialog(getSelectedFiles()[0].dataset.path);
});

btnSelectionCut.addEventListener('click', () => {
    selectionClipboard = [...getSelectedFiles()].map(el => el.dataset.path);
    const prevEls = [...$$('.cut', elFiles), ...$$('.copied', elFiles)];
    for (const el of prevEls) el.classList.remove('cut', 'copied');
    for (const path of selectionClipboard) {
        const el = $(`#files .fileEntry[data-path="${path}"]`, elFiles);
        el.classList.add('cut');
    }
    isClipboardCut = true;
    setStatus(`Cut ${selectionClipboard.length} file path(s) to selection clipboard`);
    updateDirControls();
});
btnSelectionCopy.addEventListener('click', () => {
    selectionClipboard = [...getSelectedFiles()].map(el => el.dataset.path);
    const prevEls = [...$$('.cut', elFiles), ...$$('.copied', elFiles)];
    for (const el of prevEls) el.classList.remove('cut', 'copied');
    for (const path of selectionClipboard) {
        const el = $(`#files .fileEntry[data-path="${path}"]`, elFiles);
        el.classList.add('copied');
    }
    isClipboardCut = false;
    setStatus(`Copied ${selectionClipboard.length} file path(s) to selection clipboard`);
    updateDirControls();
});
btnSelectionPaste.addEventListener('click', async() => {
    const newDirPath = activeConnection.path;
    if (!newDirPath) return;
    // Move files
    let newPaths = true;
    if (isClipboardCut) {
        // Move the files
        newPaths = await moveFiles(newDirPath, selectionClipboard);
        if (!newPaths) return;
        // Clear the clipboard
        selectionClipboard = [];
    // Copy files
    } else {
        // Copy the files
        newPaths = await copyFiles(newDirPath, selectionClipboard);
        if (!newPaths) return;
    }
    // Reload directory
    await changePath();
    // Select the new files
    for (const path of newPaths) {
        selectFile(path, false, false, true);
    }
});

btnSelectionMoveTo.addEventListener('click', () => moveFilesDialog(false));
btnSelectionCopyTo.addEventListener('click', () => moveFilesDialog(true));

btnSelectionDelete.addEventListener('click', async() => {
    const selected = [...getSelectedFiles()];
    const containsDirs = selected.some(el => el.dataset.type === 'd');
    new PopupBuilder()
        .setTitle(`Delete ${selected.length == 1 ? 'file':`${selected.length} files`}`)
        .addBodyHTML(`
            <p>Are you sure you want to delete ${selected.length == 1 ? `<b>${selected[0].dataset.name}</b>`:`these files`}?</p>
            ${containsDirs ? `<p class="text-danger">
                ${selected.length == 1 ? 'This file is a directory':'Your selection contains directories'}! Deleting ${selected.length == 1 ? 'it':'them'} will also delete everything inside of ${selected.length == 1 ? 'it':'them'}.
            </p>`:''}
            <p>This usually can't be undone!</p>
        `)
        .addAction(action => action
            .setIsDanger(true)
            .setLabel('Delete')
            .setClickHandler(async() => {
                let i = 0;
                for (const el of selected) {
                    setStatus(`Deleting file: ${el.dataset.path}`, false, Math.round((i/selected.length)*100));
                    let res = null;
                    if (el.dataset.type === 'd') {
                        res = await deleteDirectory(el.dataset.path);
                    } else {
                        res = await deleteFile(el.dataset.path);
                    }
                    i++;
                }
                setStatus(`Deleted ${selected.length} file(s)`);
                updateDirControls();
            }))
        .addAction(action => action.setLabel('Cancel'))
        .show();
});

btnDownload.addEventListener('click', () => {
    const selected = [...getSelectedFiles()];
    const rootPath = activeConnection.path;
    if (selected.length == 1) {
        if (selected[0].dataset.type === 'd') {
            downloadZip([ selected[0].dataset.path ], rootPath);
        } else {
            downloadFile(selected[0].dataset.path);
        }
    } else if (selected.length > 1) {
        downloadZip(selected.map(el => el.dataset.path), rootPath);
    } else {
        downloadZip([ activeConnection.path ], rootPath);
    }
});

btnShare.addEventListener('click', async() => {
    new PopupBuilder()
        .setTitle('Copy download link')
        .addBodyHTML(`<p>This link will allow anyone to download your selected files and folders for the next 24 hours without the need for any credentials. Make sure you aren't sharing anything sensitive!</p>`)
        .addAction(action => action
            .setLabel('Copy')
            .setIsPrimary(true)
            .setClickHandler(async() => {
                let url;
                let selected = [...getSelectedFiles()];
                const isNoneSelected = selected.length == 0;
                const isSingleSelected = selected.length == 1;
                const isMultiSelected = selected.length > 1;
                if (isNoneSelected)
                    url = await getZipDownloadUrl([activeConnection.path], activeConnection.path);
                else if (isSingleSelected) {
                    const el = selected[0];
                    if (el.dataset.type == 'd')
                        url = await getZipDownloadUrl([el.dataset.path], activeConnection.path);
                    else
                        url = await getFileDownloadUrl(el.dataset.path);
                } else if (isMultiSelected)
                    url = await getZipDownloadUrl(selected.map(el => el.dataset.path), activeConnection.path);
                if (url) {
                    navigator.clipboard.writeText(url);
                    setStatus(`Copied download link to clipboard`);
                }
            }))
        .addAction(action => action.setLabel('Cancel'))
        .show();
});
if (isLocalhost) btnShare.style.display = 'none';

btnDirView.addEventListener('click', () => {
    const menu = new ContextMenuBuilder();
    menu.addItem(item => item
        .setIcon(viewMode === 'list' ? 'check' : '')
        .setLabel('List')
        .setClickHandler(() => changeFileViewMode('list')));
    menu.addItem(item => item
        .setIcon(viewMode === 'tiles' ? 'check' : '')
        .setLabel('Tiles')
        .setClickHandler(() => changeFileViewMode('tiles')));
    menu.addSeparator();
    menu.addItem(item => item
        .setIcon(showHidden ? 'check' : '')
        .setLabel('Show hidden files')
        .setClickHandler(() => toggleHiddenFileVisibility()));
    const rect = btnDirView.getBoundingClientRect();
    menu.showAtCoords(rect.left, rect.bottom-5);
});
elFiles.classList.toggle('showHidden', showHidden);
elFiles.classList.add(viewMode);
elFileColHeadings.classList.toggle('tiles', elFiles.classList.contains('tiles'));

btnDirSort.addEventListener('click', () => {
    const menu = new ContextMenuBuilder();
    menu.addItem(item => item
        .setIcon(sortType === 'name' ? 'check' : '')
        .setLabel('Name')
        .setClickHandler(() => changeFileSortType('name')));
    menu.addItem(item => item
        .setIcon(sortType === 'date' ? 'check' : '')
        .setLabel('Modified')
        .setClickHandler(() => changeFileSortType('date')));
    menu.addItem(item => item
        .setIcon(sortType === 'size' ? 'check' : '')
        .setLabel('Size')
        .setClickHandler(() => changeFileSortType('size')));
    menu.addSeparator();
    menu.addItem(item => item
        .setIcon(!sortDesc ? 'check' : '')
        .setLabel('Ascending')
        .setClickHandler(() => changeFileSortDirection(false)));
    menu.addItem(item => item
        .setIcon(sortDesc ? 'check' : '')
        .setLabel('Descending')
        .setClickHandler(() => changeFileSortDirection(true)));
    const rect = btnDirSort.getBoundingClientRect();
    menu.showAtCoords(rect.left, rect.bottom-5);
});

btnDirSelection.addEventListener('click', () => {
    const menu = new ContextMenuBuilder()
        .addItem(item => item
            .setIcon('select_all')
            .setLabel('Select all')
            .setTooltip('Ctrl + A')
            .setClickHandler(selectAllFiles))
        .addItem(item => item
            .setIcon('select')
            .setLabel('Deselect all')
            .setTooltip('Ctrl + Shift + A')
            .setClickHandler(deselectAllFiles))
        .addItem(item => item
            .setIcon('move_selection_up')
            .setLabel('Invert selection')
            .setTooltip('Ctrl + Alt + A')
            .setClickHandler(invertFileSelection));
    const rect = btnDirSelection.getBoundingClientRect();
    menu.showAtCoords(rect.left, rect.bottom-5);
});

elFiles.addEventListener('dragover', e => {
    e.preventDefault();
    e.stopPropagation();
    elFiles.classList.add('dragover');
});
elFiles.addEventListener('dragleave', e => {
    e.preventDefault();
    e.stopPropagation();
    elFiles.classList.remove('dragover');
});
elFiles.addEventListener('drop', e => {
    e.preventDefault();
    e.stopPropagation();
    elFiles.classList.remove('dragover');
    const files = [];
    for (const file of e.dataTransfer.files) {
        if (file.type !== '') {
            files.push(file);
        }
    }
    uploadFiles(files);
});

elFiles.addEventListener('contextmenu', e => {
    e.preventDefault();
    deselectAllFiles();
    fileContextMenu();
});

window.addEventListener('click', e => {
    const matchIds = [ 'controls', 'files', 'filesFiles', 'filesFolders', 'fileColHeadings', 'statusBar' ];
    if (!matchIds.includes(e.target.id)) return;
    if (!e.ctrlKey) {
        if (getIsMobileDevice()) return;
        deselectAllFiles();
    }
});

window.addEventListener('keydown', e => {
    if (document.activeElement.tagName == 'INPUT') return;
    let func = (() => {
        if (e.ctrlKey) {
            if (e.shiftKey) {
                // Ctrl + Shift
                if (e.code === 'Space')
                    return () => connectionManagerDialog();
                if (e.code === 'KeyA')
                    return () => deselectAllFiles();
            }
            if (e.altKey) {
                // Ctrl + Alt
                if (e.code === 'KeyA') {
                    return () => invertFileSelection();
                }
            }
            // Ctrl
            if (e.code === 'KeyX')
                return () => btnSelectionCut.click();
            if (e.code === 'KeyC')
                return () => btnSelectionCopy.click();
            if (e.code === 'KeyV')
                return () => btnSelectionPaste.click();
            if (e.code === 'KeyA')
                return () => selectAllFiles();
            if (e.code === 'KeyR')
                return () => btnGo.click();
        }
        // Shift
        if (e.shiftKey) {
            if (e.code === 'KeyD')
                return () => btnDownload.click();
            if (e.code === 'KeyH')
                return () => toggleHiddenFileVisibility();
            if (e.code === 'KeyN')
                return () => btnDirCreate.click();
            if (e.code === 'KeyU')
                return () => btnUpload.click();
            if (e.code === 'KeyM')
                return () => btnSelectionMoveTo.click();
            if (e.code === 'KeyC')
                return () => btnSelectionCopyTo.click();
        }
        // Alt
        if (e.altKey) {
            if (e.code === 'ArrowLeft')
                return () => btnNavBack.click();
            if (e.code === 'ArrowRight')
                return () => btnNavForward.click();
        }
        // No modifiers
        if (e.code === 'F2')
            return () => btnRename.click();
        if (e.code === 'Delete')
            return () => btnSelectionDelete.click();
    })();
    if (func) {
        console.log(`Handling press of ${e.code}`);
        e.preventDefault();
        func();
    }
});

window.addEventListener('resize', () => {
    if (window.innerWidth < forceTileViewWidth) {
        changeFileViewMode('tiles');
    }
});

window.addEventListener('load', async() => {
    if ('serviceWorker' in navigator) {
        const registration = await navigator.serviceWorker.register('/worker.js');
        console.log('Service Worker registered with scope:', registration.scope);
    }
    const params = new URLSearchParams(window.location.search);
    const connection = connections[params.get('con') || '0'];
    if (connection) {
        setActiveConnection(params.get('con'), params.get('path'));
    } else {
        connectionManagerDialog();
    }
    window.dispatchEvent(new Event('resize'));
});

// Dynamically update file list relative dates
setInterval(() => {
    if (document.hidden) return;
    const els = $$('.fileEntry[data-date]', elFiles);
    if (els.length > 500) return;
    for (const el of els) {
        const timestamp = parseInt(el.dataset.date);
        if (!timestamp) continue;
        const elDateMain = $('.date', el);
        requestAnimationFrame(() => {
            const newText = getRelativeDate(timestamp);
            if (elDateMain.innerText == newText) return;
            elDateMain.innerText = newText;
        });
    }
}, 1000*15);