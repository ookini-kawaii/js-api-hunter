const assert = require('assert');
const net = require('net');
const { startProxyServer, stopProxyServer } = require('../out/proxy/proxyServer.js');

function listen(server) {
  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise(resolve => server.close(resolve));
}

async function reservePort() {
  const reservation = net.createServer();
  const port = await listen(reservation);
  await close(reservation);
  return port;
}

async function testConnectForwardsBufferedData() {
  let received = Buffer.alloc(0);
  let receivedData;
  const target = net.createServer(socket => {
    socket.on('data', chunk => {
      received = Buffer.concat([received, chunk]);
      receivedData?.();
    });
  });
  const targetPort = await listen(target);
  const proxyPort = await reservePort();
  let client;

  try {
    await startProxyServer(proxyPort, () => {});
    client = net.connect(proxyPort, '127.0.0.1');
    await new Promise(resolve => client.once('connect', resolve));
    const delivered = new Promise(resolve => { receivedData = resolve; });
    client.write(
      `CONNECT 127.0.0.1:${targetPort} HTTP/1.1\r\n` +
      `Host: 127.0.0.1:${targetPort}\r\n\r\nfirst-payload`
    );
    await Promise.race([
      delivered,
      new Promise((_, reject) => setTimeout(() => reject(new Error('CONNECT head was not forwarded')), 1000))
    ]);
    assert.strictEqual(received.toString(), 'first-payload');
  } finally {
    client?.destroy();
    stopProxyServer();
    await close(target);
  }
}

testConnectForwardsBufferedData()
  .then(() => console.log('PASS  CONNECT forwards buffered data'))
  .catch(error => {
    console.error(`FAIL  ${error.message}`);
    process.exitCode = 1;
  });
