// Minimal MQTT availability fixture, bound only inside an internal Docker network.
const net = require('node:net');
const mode = process.argv[2];
net.createServer(socket => {
  let buffer = Buffer.alloc(0);
  socket.on('error', () => {});
  socket.on('data', data => {
    buffer = Buffer.concat([buffer, data]);
    while (buffer.length >= 2) {
      let length = 0, multiplier = 1, offset = 1, digit;
      do { if (offset >= buffer.length) return; digit = buffer[offset++]; length += (digit & 127) * multiplier; multiplier *= 128; } while (digit & 128);
      if (buffer.length < offset + length) return;
      const type = buffer[0] >> 4, body = buffer.subarray(offset, offset + length);
      buffer = buffer.subarray(offset + length);
      if (type === 1) socket.write(Buffer.from([0x20, 2, 0, mode === 'denied' ? 5 : 0]));
      if (type === 8) {
        const topics = [];
        for (let i = 2; i < body.length;) {
          const size = body.readUInt16BE(i); i += 2;
          topics.push(body.toString('utf8', i, i + size)); i += size + 1;
        }
        socket.write(Buffer.from([0x90, 2 + topics.length, body[0], body[1], ...topics.map(() => 0)]));
        if (mode === 'missing') continue;
        for (const topic of topics) {
          if (!/^winet-extractor\/198_19_107_23\/(status|availability)$/.test(topic)) throw Error('Unexpected health subscription');
          const payload = Buffer.from(mode === 'offline' && topic.endsWith('/availability') ? 'offline' : 'online');
          const name = Buffer.from(topic), size = Buffer.alloc(2); size.writeUInt16BE(name.length);
          const packet = Buffer.concat([size, name, payload]);
          if (packet.length >= 128) throw Error('Fixture packet bound');
          socket.write(Buffer.concat([Buffer.from([0x31, packet.length]), packet]));
        }
      }
      if (type === 14) socket.end();
    }
  });
}).listen(1883, '0.0.0.0', () => console.log('fixture-ready'));
