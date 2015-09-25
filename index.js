var Tail = require('tail-forever');
var Redis = require('ioredis');
var fs = require('fs');

var localIp = /^10(\.[0-9]*){3}$/;
var isIp = /^[0-9]*(\.[0-9]*){3}$/;

var i192IP = /^192\.168(\.[0-9]*){2}$/;
var i172IP = /^172\.16(\.[0-9]*){2}$/;
var localIp = /^(10)(\.[0-9]*){3}$/;
var isIp = /^[0-9]*(\.[0-9]*){3}$/;
var config = require('./config.json');

var r = new Redis(config.redis);

var whitelist = new Set();
var urlfilter = [];
var uafilter = [];


var timestamps = {
  whitelist: 0,
  urlfilter: 0,
  uafilter: 0
};

var isCheckingTime = false;
var isUpdatingWL = false;
var isUpdatingUrl = false;
var isUpdatingUa = false;

/**
 * setting checking
 *
 */

function settingChecker() {
  if(!isCheckingTime) {
    isCheckingTime = true;

    //check timestamps
    r.mget([config.whitelistTime, config.urlfilterTime, config.uafilterTime])
    .then(function (data) {
      //console.log('@time', data);
      isCheckingTime = false;
      var newWhitelistTime = ~~data[0];
      var newUrlfilterTime = ~~data[1];
      var newUafilterTime = ~~data[2];

      var isWLChanged = newWhitelistTime > timestamps.whitelist;
      var isURLChanged = newUrlfilterTime > timestamps.urlfilter;
      var isUAChanged = newUafilterTime > timestamps.uafilter;

      if(isWLChanged) {
        if(!isUpdatingWL) {
          isUpdatingWL = true;

          r.smembers(config.whitelist).then(function (wl) {
            //console.log('@wl', wl);
            whitelist = new Set(wl);
            timestamps.whitelist = newWhitelistTime;
            isUpdatingWL = false;
          }).catch(function (err) {
            console.log(err);
            isUpdatingWL = false;
          });
        }
      }

      if(isURLChanged) {
        if(!isUpdatingUrl) {
          isUpdatingUrl = true;
          r.smembers(config.urlfilter).then(function (url) {
            //console.log('@url', url);
            urlfilter = url;
            timestamps.urlfilter = newUrlfilterTime;
            isUpdatingUrl = false;
          }).catch(function (err) {
            console.log(err);
            isUpdatingUrl = false;
          });
        }
      }
      if(isUAChanged) {
        if(!isUpdatingUa) {
          isUpdatingUa = true;
          r.smembers(config.uafilter).then(function (ua) {
            var newfilter = [];
            ua.forEach(function(u) {
              try {
                u = JSON.parse(u);
                newfilter.push(u);
              } catch(err) {
                console.log(err);
              }
            });
            uafilter = newfilter;
            timestamps.uafilter = newUafilterTime;
            isUpdatingUa = false;
          }).catch(function (err) {
            console.log(err);
            isUpdatingUa = false;
          });
        }
      }
    }).catch(function (err) {
      console.log(err);
      isCheckingTime = false;
    });
  }
}

settingChecker();
setInterval(settingChecker, 10000);



if(!config.logPath) {
  console.log('must provide logPath in config');
  return;
}

var start = 0;
//only try to check file stat if file exists
if(fs.existsSync(config.logPath)) {
  var stat = fs.statSync(config.logPath);
  start = stat.size;
}

var tail = new Tail(config.logPath, {
  start: start
});



tail.on('line', processLine);


function processLine(data) {
  try {
    data = JSON.parse(data);
  } catch (err) {
    console.log(err);
    return;
  }
  var ip = data.remote_addr;
  var status = data.status;

  if(isIp.test(ip)) {
    //check for local ip and whitelist ips
    if('127.0.0.1' ===ip ||
       whitelist.has(ip) ||
         localIp.test(ip) ||
           i192IP.test(ip) ||
             i172IP.test(ip)) {
      return;
    }

    //check for offenders
    if(status === '444' ||
       checkUrl(data.http_referrer) ||
       checkUa(data.http_user_agent)
      ) {
      r.zincrby(config.ban, 0, ip).catch(console.log);
    }


  }
}

function checkUrl(url) {
  for(var i = 0, len = urlfilter.length; i < len; i++) {
    if(url.indexOf(urlfilter[i]) > -1) {
      return true;
    }
  }
  return false;
}

function checkUa(ua) {
  for(var i = 0, len = uafilter.length; i < len; i++) {
    if(uafilter[i].every(function(u) {
      return ua.indexOf(u) > -1;
    })) {
      return true;
    }
  }
  return false;
}

