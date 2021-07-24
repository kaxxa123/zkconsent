// hello.js
const addon = require('./build/Release/nodegw');

console.log(addon.hello());
// Prints: 'world'