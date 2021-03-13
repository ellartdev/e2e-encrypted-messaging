let randNum = (digit) => {
    let letters = "0123456789AĀĄBCČDEĒĘĖFGĢHIĪĮJKĶLĻMNŅOPQRSŠZŽTUŪŲVWÕÄÖÜXY"; // full est/lv/lt alphabet and numbers
	let code = "";
	for (let i = 0; i < digit; i++) {
		code += letters[Math.floor(Math.random() * letters.length)];
	};
	return code;
};

$(() => {
    let clientID = randNum(5);
    let socket = io(`/?clientId=${clientID}`);
    $('form').submit((e) => {
        e.preventDefault(); // prevents page reloading
        socket.emit('chat-message', {
            from: clientID,
            to: 'all',
            msg: $('#m').val()
        });
        $('#m').val('');
        return false;
    });
    socket.on('decrypted-msg', (data) => {
        $('#messages').append(`<li id="message">${data.msg}</div>`);
    });
});
