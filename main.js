const address = window.location.href;
console.log(address);

const socket = new WebSocket(address);
console.log(socket);
