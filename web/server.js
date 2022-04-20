require('dotenv').config('./env');

const zlib = require('zlib');
const express = require('express');
const app = express();
const IO = require('socket.io');
const Redis = require('ioredis');
const redis = new Redis({
	host: process.env.REDIS_HOST || '127.0.0.1', // Redis host
	port: process.env.REDIS_PORT || 6379, // Redis port
	family: process.env.REDIS_FAMILY || 4, // 4 (IPv4) or 6 (IPv6)
	password: process.env.REDIS_PASSWORD || '',
	db: process.env.REDIS_DB || 0,
});
const moment = require("moment");
const cookieParser = require('cookie-parser');
const logger = require('morgan');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static('public'));
app.post('/send', function(req, res) {
	const room = req.body.room;
	const name = req.body.name;
	const message = req.body.message;
	io.to(room).emit('chat', {name,message});
	res.send('Sent');
	res.end();
});

app.set('port', process.env.PORT || 6001);
const http = require('http');
const server = http.createServer(app);
server.listen(app.get('port'), function() {
	console.log('Server is running, listen on port ' + app.get('port'));
});

const io = IO(server);
const keys = {};
const runs = {};

io.on('connection', function(socket) {
	socket.on('disconnect', function() {
		console.log(socket.name + ' leave room ' + socket.room);
		io.to(socket.room).emit('leave', socket.name);
		socket.leave(socket.room);

		keys[socket.room]--;
	});
	socket.on('join', function(join) {
		console.log(join.name, 'join', join.room);
		socket.join(join.room);
		
		socket.name = join.name;
		socket.room = join.room;
		io.to(socket.room).emit('join', socket.name);

		if(socket.room in keys) keys[socket.room]++;
		else keys[socket.room] = 1;
		
		if(!runs[socket.room]) popId(socket.room);
	});
	socket.on('message', function(message) {
		console.log('Receive message:', message);
		socket.send(message);
	});
	socket.on('time', function() {
		const t = moment().format('YYYY-MM-DD HH:mm:ss');
		console.log('time:', socket.room, socket.name, t);
		io.to(socket.room).emit('time', {name:socket.name, time:t});
	});
	socket.on('off', function(off) {
		redis.set(socket.room + ':off', off, function(err, result) {
			io.to(socket.room).emit('off', {name: socket.name, off:off, result: result});
		});
	});
});

const getResponse = function(key, id, info) {
	redis.getBuffer(key+':'+id+':response', function(err, result) {
		if(err) nextId(key, err, info);
		else {
			if(info.contentEncoding === 'gzip') {
				result = zlib.gunzipSync(result);
			} else if(info.contentEncoding === 'deflate') {
				result = zlib.inflateSync(result);
			}

			info.responseText = result ? result.toString() : '';
			
			redis.del(key+':'+id);
			redis.del(key+':'+id+':'+'post');
			redis.del(key+':'+id+':'+'response');

			nextId(key, err, info);
		}
	});
};

const getPost = function(key, id, info) {
	redis.getBuffer(key+':'+id+':post', function(err, result) {
		if(err) nextId(key, err, info);
		else {
			info.postText = result ? result.toString() : '';
			
			getResponse(key, id, info);
		}
	});
};

const getInfo = function(key, id) {
	redis.hgetall(key+':'+id, function(err, result) {
		if(err) nextId(key, err);
		else if(result) {
			result.responseCode = parseInt(result.responseCode);
			result.serverPort = parseInt(result.serverPort);
			result.runTime = parseFloat(result.runTime);
			result.dumpId = id;
			
			getPost(key, id, result);
		} else getPost(key, id, {dumpId:id});
	});
};

const popId = function(key) {
	runs[key] = true;

	redis.lpop(key, function(err, result) {
		if(result) getInfo(key, result);
		else nextId(key, err, result);
	});
};

const nextId = function(key, err, info) {
	if(err) console.error(key, err);

	if(info) io.to(key).emit('dump', info);

	if(keys[key] > 0) {
		if(info) popId(key);
		else setTimeout(function() {
			popId(key);
		}, 10);
	} else {
		runs[key] = false;
	}
};
