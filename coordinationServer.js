const server = require('http').createServer((req, res) => {
    res.writeHead(404, {
        'Content-Type': 'text/html'
    });
    res.end('<p>four null four<p>');
}); // Coordination server for coordinating public keys and encrypted messages between crypto proxy.
let io = require('socket.io');

const port = 3001;  // Coordination server port
let clients = [],   // Clients currently connected
    keys = [],      // Public keys currently being coordinated by the server 

    // Helper variables for key cleanup
    key_cleanup = [],
    outstanding_requests = 0;
    keyRefreshInterval = 2000; // 2 seconds

let propagateKeys = () => {
    for (let i in clients) {
        clients[i].emit('broadcast-pub-keys', keys);
    };
};

// Let's make a socket :3
server.listen(port);
io = io.listen(server);

// When crypto proxy has connected to the server
io.sockets.on('connection', (socket) => {
    console.log("Connected to crypto proxy")
    clients.push(socket);

    socket.on('chat-message', (msg) => {
        clients.forEach((client) => {
            client.emit('chat-message', msg);
        });
    });

    socket.on('new-keypair', (data) => {
        /**
         * Crypto proxy sends new public key
         * Checks if it's already being tracked
         * If not, adds to the keys list
         */

        if (keys.filter((k) => {
            return k.id === data.id;
        }).length === 0) {
            keys.push(data);
        };

        propagateKeys();
    });

    socket.on('del-keypair', (data) =>  {
        clients.forEach((c) => {
            c.emit('del-keypair', { id: data.id });
        });

        keys = keys.filter((k) => {
            return k.id !== data.id;
        });
    });

    socket.on('all-keys', (data) => {
        /**
         * Crypto proxy responds with its keys
         * Decrements outstanding requests variable
         * Knowing that server has all of them it has sent
         * using the setInterval function in the bottom
         */
        outstanding_requests -= 1;
        data.keys.forEach((key) => {
            key_cleanup.push(key);
        });
        if (outstanding_requests === 0) {
            // replace keys with key cleanup array
            keys = [];
            key_cleanup.forEach((key) => {
                keys.push(key);
            });
            propagateKeys();
        };
    });

    // When crypto proxy gets disconnected
    socket.on('disconnect', () => {
        clients = clients.filter((c) => {
            return c !== socket;
        });
        console.log(`Disconnected from crypto proxy`);
    });
});

setInterval(() => {
    outstanding_requests = 0;
    key_cleanup = [];
    clients.forEach((c) => {
        outstanding_requests++;
        c.emit('key-cleanup', {});
    });
}, keyRefreshInterval);
