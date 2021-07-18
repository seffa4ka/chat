const dotenv = require('dotenv');
const http = require('http');
const crypto = require('crypto');
const mysql = require('mysql');
const passport = require('passport');
const BearerStrategy = require('passport-http-bearer').Strategy;
const Router = require('koa-router');
const Koa = require('koa');
const app = new Koa();
const cors = require('@koa/cors');
const bodyParser = require('koa-bodyparser');
const router = new Router();
const {Server} = require("socket.io");

dotenv.config();
const dbConfig = {
    host: process.env.MYSQL_HOST,
    port: process.env.MYSQL_PORT,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE
};
app.use(cors());
app.use(bodyParser());
let connection;
let IOConnections = [];
const handleDb = () => {
    connection = mysql.createConnection(dbConfig);
    connection.connect((err) => {
        if (err) setTimeout(handleDb, 2000);
    });
    connection.on('error', (err) => {
        if (err.code !== 'PROTOCOL_CONNECTION_LOST') throw err;
        handleDb();
    });
};
handleDb();
passport.use('bearer', new BearerStrategy((token, done) => {
    async function getUserId() {
        return await new Promise((resolve, reject) => {
            const ts = Math.round(new Date() / 1000);
            let sql = "SELECT user_id FROM `tokens` WHERE `access_token`=? AND `access_expired`>?";
            connection.query(sql, [token, ts], (err, result) => {
                if (err) return reject(err);
                resolve(result);
            })
        });
    }

    async function getUserById(id) {
        return await new Promise((resolve, reject) => {
            let sql = "SELECT id, login FROM `user` WHERE `id`=?";
            connection.query(sql, [id], (err, result) => {
                if (err) return reject(err);
                resolve(result);
            })
        })
    }

    getUserId()
        .then((userData) => {
            if (!userData.length) return done(null, false);
            const {user_id} = userData[0];
            return user_id;
        })
        .then(getUserById)
        .then((user) => {
            if (!user.length) return done(null, false);
            return done(null, user[0], {scope: 'all'})
        })
        .catch((error) => done(error, null))
}));
router.post('/sign-in', async (ctx) => {
    const {login, password} = ctx.request.body;

    if (!login || !password) ctx.throw(400);

    const exist = await new Promise((resolve, reject) => {
        let sql = "SELECT id, password FROM `user` WHERE `login`=?";
        connection.query(sql, [login], (err, result) => {
            if (err) return reject(err);
            resolve(result);
        })
    });

    if (!exist.length) ctx.throw(422);

    const hash = crypto.pbkdf2Sync(password, process.env.SALT, 1000, 64, `sha512`).toString(`hex`)

    if (exist[0].password !== hash) ctx.throw(422);

    const userId = exist[0].id;
    const ts = Math.round(new Date() / 1000);
    const refreshToken = crypto.randomBytes(32).toString('hex');
    const accessToken = crypto.randomBytes(32).toString('hex');
    const refreshExpired = ts + parseInt(process.env.REFRESH_EXPIRED);
    const accessExpired = ts + parseInt(process.env.ACCESS_EXPIRED);
    let sql = "SELECT id FROM `tokens` WHERE `user_id`=? AND `refresh_expired`<?";
    const getTokens = await new Promise((resolve, reject) => {
        connection.query(sql, [userId, ts], (err, result) => {
            if (err) return reject(err);
            resolve(result);
        })
    });

    if (getTokens.length) {
        const updateTokens = await new Promise((resolve, reject) => {
            let sql = "UPDATE `tokens` SET `access_token`=?, `access_expired`=?, `refresh_token`=?, `refresh_expired`=? WHERE `user_id`=?";
            connection.query(sql, [accessToken, accessExpired, refreshToken, refreshExpired, userId], (err, result) => {
                if (err) return reject(err);
                resolve(result);
            })
        });

        if (!updateTokens) ctx.throw(500);
    } else {
        const addTokens = await new Promise((resolve, reject) => {
            let sql = "INSERT INTO `tokens` (id, user_id, refresh_token, access_token, refresh_expired, access_expired) VALUES ?";
            let values = [[null, userId, refreshToken, accessToken, refreshExpired, accessExpired]];
            connection.query(sql, [values], (err, result) => {
                if (err) return reject(err);
                resolve(result);
            });
        });

        if (!addTokens) ctx.throw(500);
    }

    ctx.set('Content-Type', 'application/json');
    ctx.body = {refresh_token: refreshToken, access_token: accessToken, ts_expired: accessExpired};
}).post('/sign-up', async (ctx) => {
    const {login, password} = ctx.request.body;

    if (!login || !password) ctx.throw(400);

    if (login.length < 6 || login.length > 16 || password.length < 6) ctx.throw(422);

    const exist = await new Promise((resolve, reject) => {
        let sql = "SELECT login FROM `user` WHERE `login`=?";
        connection.query(sql, [login], (err, result) => {
            if (err) return reject(err);
            resolve(result);
        })
    });

    if (!!exist.length) ctx.throw(422);

    const addUser = await new Promise((resolve, reject) => {
        let sql = "INSERT INTO `user` (id, login, password) VALUES ?";
        let values = [[null, login, crypto.pbkdf2Sync(password, process.env.SALT, 1000, 64, `sha512`).toString(`hex`)]];
        connection.query(sql, [values], (err, result) => {
            if (err) return reject(err);
            resolve(result);
        });
    });

    if (!addUser) ctx.throw(500);

    ctx.set('Content-Type', 'application/json');
    ctx.body = {};
}).post('/refresh', async (ctx) => {
    const {refresh_token} = ctx.request.body;

    if (!refresh_token) ctx.throw(400);

    const ts = Math.round(new Date() / 1000);
    const exist = await new Promise((resolve, reject) => {
        let sql = "SELECT id FROM `tokens` WHERE `refresh_token`=? AND `refresh_expired`>?";
        connection.query(sql, [refresh_token, ts], (err, result) => {
            if (err) return reject(err);
            resolve(result);
        })
    });

    if (!exist.length) ctx.throw(404);

    const accessToken = crypto.randomBytes(32).toString('hex');
    const accessExpired = ts + parseInt(process.env.ACCESS_EXPIRED);
    const updateToken = await new Promise((resolve, reject) => {
        let sql = "UPDATE `tokens` SET `access_token`=?, `access_expired`=? WHERE `refresh_token`=?";
        connection.query(sql, [accessToken, accessExpired, refresh_token], (err, result) => {
            if (err) return reject(err);
            resolve(result);
        })
    });

    if (!updateToken) ctx.throw(500);

    ctx.set('Content-Type', 'application/json');
    ctx.body = {access_token: accessToken, ts_expired: accessExpired};
}).post('/session', async (ctx) => {
    const user = await new Promise((resolve) => {
        passport.authenticate('bearer', {session: false}, (_, user) => resolve(user))(ctx);
    });

    if (!user) ctx.throw(401);

    const ts = Math.round(new Date() / 1000);
    const sessions = await new Promise((resolve, reject) => {
        let sql = "SELECT refresh_token FROM `tokens` WHERE `refresh_expired`>? OR `access_expired`>?";
        connection.query(sql, [ts, ts], (err, result) => {
            if (err) return reject(err);
            resolve(result);
        })
    });

    ctx.set('Content-Type', 'application/json');
    ctx.body = sessions;
}).post('/sign-out', async (ctx) => {
    const {refresh_token} = ctx.request.body;

    if (!refresh_token) ctx.throw(400);

    const ts = Math.round(new Date() / 1000);
    const updateToken = await new Promise((resolve, reject) => {
        let sql = "UPDATE `tokens` SET `refresh_expired`=?, `access_expired`=? WHERE `refresh_token`=?";
        connection.query(sql, [ts, ts, refresh_token], (err, result) => {
            if (err) return reject(err);
            resolve(result);
        })
    });

    if (!updateToken) ctx.throw(500);

    ctx.set('Content-Type', 'application/json');
    ctx.body = {};
}).get('/timestamp', (ctx) => {
    const ts = Math.round(new Date() / 1000);
    ctx.set('Content-Type', 'application/json');
    ctx.body = {ts};
}).post('/owner', async (ctx) => {
    const user = await new Promise((resolve) => {
        passport.authenticate('bearer', {session: false}, (_, user) => resolve(user))(ctx);
    });

    if (!user) ctx.throw(401);
    ctx.set('Content-Type', 'application/json');
    ctx.body = user;
});

app.use(router.routes());
const server = http.createServer(app.callback())
const io = new Server(server, {cors: {origin: '*'}});
io.on('connection', (socket) => {
    IOConnections.push(socket);
    socket.on('disconnect', () => IOConnections.splice(IOConnections.indexOf(socket), 1));
    socket.on('chat message', msg => io.emit('chat message', msg));
});

server.listen(process.env.PORT);
