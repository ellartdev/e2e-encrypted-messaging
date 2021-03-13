const express = require('express');
const app = express();
const favicon = require('serve-favicon');

// for TLS/SSL
const fs = require('fs');
const cert = fs.readFileSync('./.ssh/cert.pem', 'utf-8');
const key = fs.readFileSync('./.ssh/key.pem', 'utf-8');
const sertopts = {cert: cert, key: key};

/**
 * Crypto proxy
 * Registers web clients
 * Generates keys for them
 */
const https = require('https').createServer(sertopts, app); // create HTTPS server
const clientio = require('socket.io')(https); // create socket
const crypto = require('crypto');

const PORT = 443;       // Crypto proxy server port
const IV_LENGTH = 16;   // Initialization vector's length
                        // for AES256, it's 16

let findKey = (id) => {
    let keyfound = false,
        returnkey,
        type;
    
    private_keys.forEach((key) => {
        if (key.id.indexOf(id) !== -1) {
            keyfound = true;
            returnkey = key;
            type = 'private';
        };
    });

    if (!keyfound) {
        public_keys.forEach((key) => {
            if (key.id.indexOf(id) !== -1) {
                keyfound = true;
                returnkey = key;
                type = 'public';
            };
        });
    };

    if (keyfound) {
        return {
            search_id: id,
            key: returnkey,
            type: type
        };
    } else {
        return -1;
    };
};

let private_keys = [],
    public_keys = [],
    sockets = [];

// When web client establishes a connection
clientio.on('connection', async (socket) => {
    socket.id = socket.handshake.query.clientId; // unique ID
    sockets.push(socket);

    console.log(`${socket.id} joined`);

    // Generating key object for the client
    let keypair = crypto.getDiffieHellman('modp14');
    keypair.generateKeys(); // gen em keys!

    // Add to private key list
    private_keys.push({
        id: socket.id,
        keypair: keypair
    });

    // Add hex text of public key to public keys list
    public_keys.push({
        id: socket.id,
        public_key: keypair.getPublicKey('hex')
    });

    // Sends new fresh-baked public key to coordination server
    servsocket.emit('new-keypair', {
        id: socket.id,
        public_key: keypair.getPublicKey('hex')
    });

    socket.on('chat-message', (msg) => {
        /**
         * Receiving usual message from web client / browser
         * Encrypting it for everyone in public keys
         * Emitting to coordination server as chat-message event
         */

        let from_keypair;
        private_keys.forEach((key) => {
            if (key.id.indexOf(msg.from) !== -1) {
                from_keypair = key.keypair;
            };
        });
        if (from_keypair === undefined) {
            return;
        };

        if (msg.to === 'all') {
            // for every user's public key
            public_keys.forEach((key) => {

                // ENCRYPTION TIME

                // DEPRECATED SOLUTION
                // let sharedSecret = from_keypair.computeSecret(key.public_key, 'hex', 'hex');
                // let password = crypto.createHash('sha256').update(sharedSecret).digest();
                // let cipher = crypto.createCipher('aes256', password);
                // let cipher_text = Buffer.concat([cipher.update(msg.msg), cipher.final()]);

                let iv = crypto.randomBytes(IV_LENGTH); // gen random IV with set length

                // calc shared secret
                let sharedSecret = from_keypair.computeSecret(key.public_key, 'hex', 'hex');

                // create 256-bit hash of shared secret for using as the AES key
                let password = crypto.createHash('sha256').update(sharedSecret).digest();

                /**
                 * Encrypt message using the hash of the shared secret as password
                 * Along with randomly generated initialization vector input
                 */
                let cipher = crypto.createCipheriv('aes256', Buffer.from(password), iv);

                // Create cipher text using encryption object
                let encrypted = Buffer.concat([cipher.update(msg.msg), cipher.final()]);
                
                servsocket.emit('chat-message', {
                    from: msg.from,
                    to: key.id,
                    msg: `${iv.toString('hex')}:${encrypted.toString('hex')}`
                });
            });
        };
    });

    socket.on('disconnect', () => {
        servsocket.emit('del-keypair', {
            id: socket.id
        });

        sockets = sockets.filter((s) => {
            return s !== socket;
        });

        console.log(`${socket.id} left`);
    });
});


const server_io = require('socket.io-client');
const servsocket = server_io.connect(`http://localhost:3001`, {
    reconnection: true
});

// Establishing connection with coordination server
servsocket.on('connect', () => { console.log('Connected to coordination server'); });

servsocket.on('key-cleanup', () => {
    /**
     * Coordination server wants for client to send all public keys
     * it has private keys for, which are also currently connected
     * clients
     */
    let currentClientIds = [];
    sockets.forEach((s) => {
        currentClientIds.push(s.id);
    });
    let newPrivateKeys = [];
    private_keys.forEach((pk) => {
        if (currentClientIds.indexOf(pk.id) !== -1) {
            newPrivateKeys.push(pk);
        };
    });
    private_keys = newPrivateKeys;

    let publicKeyIds = [];
    public_keys.forEach((key) => {
        publicKeyIds.push(key.id);
    });

    let msg = {
        keys: []
    };
    private_keys.forEach((k) => {
        msg.keys.push({
            id: k.id,
            public_key: k.keypair.getPublicKey('hex')
        });
    });

    // Sending all keys to the server
    servsocket.emit('all-keys', msg);
});

servsocket.on('broadcast-pub-keys', (data) => {
    // Receiving new set of public keys from server
    public_keys = data;
});

servsocket.on('new-keypair', (data) => {
    // Adding keypair to keys

    if (public_keys.filter((k) => {
        return k.id === data.id;
    }).length === 0) {
        public_keys.push(data);
    };
});

servsocket.on('del-keypair', (data) => {
    // Remove key from keys where data.id = k.id
    public_keys = public_keys.filter((k) => {
        return k.id !== data.id;
    });
});

servsocket.on('chat-message', (data) => {
    /**
     * chat-message listener from coordination server
     * Finds private key for to ID
     * Finds public key for from ID
     * Decrypts message
     * Emits decrypted message to client with matching to.id
     */
    console.log(`Encrypted message from server, ${data.from} ${data.to}`);
    let keyA = findKey(data.to);
    let keyB = findKey(data.from);

    let privateKeyObj, publicKeyHex;
    if (keyA.type === 'private' && keyB.type === 'public') {
        privateKeyObj = keyA.key.keypair;
        publicKeyHex = keyB.key.public_key;
    } else if (keyA.type === 'public' && keyB.type === 'private') {
        privateKeyObj = keyB.key.keypair;
        publicKeyHex = keyA.key.public_key;
    } else if (keyA.type === 'private' && keyB.type === 'private') {
        privateKeyObj = keyA.key.keypair;
        publicKeyHex = keyB.key.keypair.getPublicKey('hex');
    } else {
        return console.log('no private key found for message');
    };

    // DEPRECATED SOLUTION
    // let sharedSecret = privateKeyObj.computeSecret(publicKeyHex, 'hex', 'hex');
    // let password = crypto.createHash('sha256').update(sharedSecret).digest();
    // let decipher = crypto.createDecipher('aes256', password);
    // let plainText = Buffer.concat([decipher.update(Buffer.from(data.msg, 'hex')), decipher.final()]);

    // Calc shared secret from public key hex
    let sharedSecret = privateKeyObj.computeSecret(publicKeyHex, 'hex', 'hex');

    // Create 256-bit hash of shared secret for using as the AES key
    let password = crypto.createHash('sha256').update(sharedSecret).digest();

    /**
     * Split message into two parts
     * IV and encrypted part
     */
    let msgParts = data.msg.split(':');
    let iv = Buffer.from(msgParts.shift(), 'hex');
    let encryptedText = Buffer.from(msgParts.join(':'), 'hex');

    // Decrypt message
    let decipher = crypto.createDecipheriv('aes256', Buffer.from(password), iv);
    let decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);

    let decryptedData = {
        from: data.from,
        to: data.to,
        msg: decrypted.toString()
    };

    // Emit to web client / browser with id to data.to
    sockets.forEach((s) => {
        if (s.id.indexOf(data.to) !== -1) {
            s.emit('decrypted-msg', decryptedData);
        };
    });
    return;
});

// Web server stuff
app.use('/client', express.static('client'));
app.use('/scripts', express.static('client/scripts'))
app.use('/css', express.static('client/css'))
app.use(favicon('favicon.ico'));

app.get('/', (req, res) => {
    res.sendFile(`${__dirname}/client/views/index.html`);
});

https.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);
});
