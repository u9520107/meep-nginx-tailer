var Tail = require('tail-forever');
var Redis = require('ioredis');
var fs = require('fs');

var localIp = /^10(\.[0-9]*){3}$/;
var isIp = /^[0-9]*(\.[0-9]*){3}$/;
var configPath = process.argv[2];

var 192IP = /^192\.168(\.[0-9]*){2}$/;
var 172IP = /^172\.16(\.[0-9]*){2}$/;
var localIp = /^(10)(\.[0-9]*){3}$/;
var isIp = /^[0-9]*(\.[0-9]*){3}$/;
var config = JSON.parse(fs.readFileSync(configPath));

var r = new Redis(config.redis);

if(!config.logPath) {
  console.log('must provide logPath in config');
  return;
}

var stat = fs.statSync(config.logPath);

var tail = new Tail(config.logPath, {
  start: stat.size
});



tail.on('line', processLine);


function processLine(data) {
  data = data.split(' ');
  var ip = data[0];
  if(isIp.test(ip) &&
     '127.0.0.1' !== ip &&
     !localIp.test(ip) &&
     !192IP.test(ip) &&
     !172IP.test(ip) &&
       data[8] === '499' ) {

    r.zincrby('iptables-ban', 0, ip).catch(console.log);
  }
}

