// Existing DOM harness uses in-memory fetch fixtures; no browser or network.
const blocked = () => { throw new Error('Offline test runner blocked network access'); };
require('net').Socket.prototype.connect = blocked;
require('http').request = require('https').request = blocked;
require('http').get = require('https').get = blocked;
require('dns').lookup = blocked;
global.fetch = blocked;
require('./frontend.test.cjs');
