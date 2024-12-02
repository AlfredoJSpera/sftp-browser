# sftp-browser

To run the server:
```shell
npm run startserver
```

## Changes

-   Instead of storing connections in the client browser, these are now stored in the server
    -   On window load (`index.js`, `window.addEventListener('load', ...)`) get the stored connections

```js
if (Object.keys(connections).length === 0) {
	console.log("Connections not loaded yet, waiting...");
	await initializeConnections();
}
```

## Flow

### No connections stored
```mermaid
sequenceDiagram
    participant H as index.html
    participant M as main.js
    participant I as index.js
    participant S as server.js

    H->>M: Call
    M->>M: Load variables (connections)
    H->>I: Call
    I->>I: initializeConnections()
    I->>I: connectionManagerDialog()
    H->>I: Press `create new connection`
    I->>I: addNewConnectionDialog()
    I->>I: connections[id] = empty connection parameters
    I->>I: editConnectionDialog(id)
    I-->>H: show form dialog (id)
    H->>I: fill form dialog (data, id)
    I->>I: connections[id] = data
    I->>S: saveConnections() => HTTP POST /api/sftp/connections/edit (connections)
    S->>S: connection_objects = connections

```