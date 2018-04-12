/*
* Module's dependencies
*/
var SF      = require('node-salesforce');
var Cache   = require("mem-cache");
var uuid    = require("node-uuid");
var request = require('request');
var jwtflow = require('./jwtflow.js');

var Salesforce = function(settings) {
    // Initialize members
    var self    = this;
    var config  = settings;
    var cacheTimeout =  (!settings || !settings.timeout ) ? 15 * 60 * 1000 : settings.timeout; // 15 minutes in milliseconds
    var isSandbox = (config && config.isSandbox);
    
    var cacheOptions = {timeout: cacheTimeout};
    var cacheUser = new Cache(cacheOptions);
    Object.defineProperty(this, "cacheAuth", {
        enumerable: false,
        configurable: false,
        writable: false,
        value: new Cache(cacheOptions)
    });

    self.cacheAuth.on("expired", function (keyValue) {
        // removes entry from user cache
        if (!keyValue || !keyValue.value) return;
        cacheUser.remove(keyValue.value.username);
        if (typeof keyValue.value.connection === 'function') keyValue.value.connection.logout();
    });

    // jwtFlow must use a new connection on each request, because no token-refresh procedure was implemented,
    // so when jwtFlow was configured, the connector will return always the same auth token
    // in order to simplify the cache managment.

    var jwtFlowAuthToken = uuid.v4(); // Internal auth token;
    var auth;

    this.authenticate = function (credentials, cb) {
        console.log(cacheTimeout);
        if (!cb && typeof credentials === 'function') {
            cb = credentials;
            credentials = config;
        }

        // defaults for cb
        cb = cb || function(err) { if(err) throw err; };
        if (typeof cb !== 'function') return cb(new Error("'cb' argument is invalid."));
        if (!credentials || typeof credentials !== 'object') return  cb(new Error("'credentials' argument is invalid."));

        // auth using JWT Flow
        if (credentials.useOAuthJwtFlow || config.useOAuthJwtFlow) return authenticateUsingJwtFlow(credentials, function (err, cn) {
            if (err) return cb(err);
            cn.logout();
            return cb(null, { auth: jwtFlowAuthToken });
        });

        account = credentials.username || config.username; 
        secret = credentials.password || config.password;           

       // Validates user credentials
        if (!account || typeof (account) !== 'string') return cb(new Error("'username' property is missing or invalid."));
        if (!secret || typeof (secret) !== 'string') return cb(new Error("'password' property is missing or invalid."));

        // try to find if a connection is not in the cache
        auth = cacheUser.get(account);
        if (auth) {
            var item = self.cacheAuth.get(auth);
            if (item && item.password === secret) return cb(null, { auth: auth });
            return cb (new Error("invalid username or password."));
        }

        var sfConnection;
        
        if (credentials.oauth2 && typeof credentials.oauth2 == 'object') {
            if (typeof (credentials.oauth2.clientSecret) !== 'string') return cb(new Error("'oauth2.clientSecret' property is invalid."));
            
            if (isSandbox) {
                sfConnection = new SF.Connection({ oauth2: credentials.oauth2, loginUrl: 'https://test.salesforce.com' });
            } else {
                sfConnection = new SF.Connection(credentials.oauth2);
            }
        } else {
            var sfOptions = {};
            if (isSandbox) sfOptions.loginUrl = 'https://test.salesforce.com';
            sfConnection = new SF.Connection(sfOptions);
        }

        sfConnection.login(account, secret, function (err, userInfo) {
            if (err) return cb(err);
            
            var item = {
                auth: uuid.v4(), // Internal auth token 
                username: account,
                password: secret,
                connection: sfConnection
            };

            self.cacheAuth.set(item.auth, item);  
            cacheUser.set(account, item.auth);
            auth = item.auth;
            console.log("Auth"+auth);
            cb(null, { auth: item.auth });
        });
        console.log(auth);
    };

    var getSFConnection = function (options, cb) {

        if (options.auth) {
            
            if (options.auth === jwtFlowAuthToken) {
                if (!options.useOAuthJwtFlow && !config.useOAuthJwtFlow) return cb(new Error("Invalid 'auth' token."));
                authenticateUsingJwtFlow(options, cb);
                return;
            }

            // searchs auth token at the cache
            var item = self.cacheAuth.get(options.auth);
            if (!item) return cb(new Error("Invalid 'auth' token."));
            return cb(null, item.connection, options.auth);
        }

        // defaults for credentials
        var credentials = options.credentials || config;
        var metadata = options._kidozen || options.metadata;

        if (metadata && metadata.userClaims) {
            var claimType = credentials.userNameClaimType || 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress';
            
            credentials.actAsUsername = (metadata.userClaims.filter(function(c) { 
                return c.type == claimType; 
            })[0] || {}).value;

            if (!credentials.actAsUsername) return cb(new Error('Claim type "' + claimType + '" was not found in user claims.'));
        }

        // auth using JWT Flow
        if (credentials.useOAuthJwtFlow || config.useOAuthJwtFlow) return authenticateUsingJwtFlow(credentials, cb);

        self.authenticate(credentials, function (err, data) {
            if (err) return cb(err);

            var item = self.cacheAuth.get(data.auth);  
            cb(null, item.connection, data.auth);
        });
    };

    var authenticateUsingJwtFlow = function (credentials, cb) {

        var privateKey = credentials.privateKey || config.privateKey;
        if (!privateKey) {
            cb(new Error('credentials.privateKey is required when using OAuth JWT Bearer Flow.'));
            return;
        };

        var clientId = credentials.clientId || config.clientId;
        if (!clientId) {
            cb(new Error('credentials.clientId is required when using OAuth JWT Bearer Flow.'));
            return;
        };

        var actAsUsername = credentials.actAsUsername || config.actAsUsername;
        if (!actAsUsername) {
            cb(new Error('credentials.username is required when using OAuth JWT Bearer Flow.'));
            return;
        };

        jwtflow(clientId, privateKey, actAsUsername, isSandbox, config.customTokenEndpoint, function (err, accessToken) {
            if (err) return cb(err);

            var options = {
              instanceUrl: 'https://' + (credentials.loginHost || config.loginHost),
              accessToken: accessToken
            };

            var sfConnection = new SF.Connection();
            sfConnection.initialize(options);
            cb(null, sfConnection, jwtFlowAuthToken);
        });
    };

    this.close = function(cb) {
        cb = cb || function(){};
        var keys = self.cacheAuth.keys;
        var count = keys.length;

        cacheUser.clean();
        if (!count) return cb();

        keys
            .forEach(function (key) {
                var item = self.cacheAuth.remove(key);
                if (item) { 
                    item.connection.logout(function() {
                        if (--count==0) cb();
                    });
                } else {
                    if (--count==0) cb();
                }
            });
    };

    this.Query = function(options, cb) {
        console.log("-------------");
        console.log(auth);
        getSFConnection(options, function (err, cn) {
            if (err) return cb(err);

            if (options.SOSQL) return cn.query(options.SOSQL, cb);

            cn
            .sobject(options.Entity)
            .find(options.Conditions, options.Fields, options.Options, cb);

            if (auth===jwtFlowAuthToken) cn.logout();
        });
    };

    this.Describe = function(options, cb) {
        
        getSFConnection(options, function (err, cn, auth) {
            if (err) return cb(err);

            cn.sobject(options.objectClass).describe(cb);

            if (auth===jwtFlowAuthToken) cn.logout();
        });
    };

    this.DescribeGlobal = function(options, cb) {
        
        getSFConnection(options, function (err, cn, auth) {
            if (err) return cb(err);

            cn.describeGlobal(cb);

            if (auth===jwtFlowAuthToken) cn.logout();
        });
    };

    this.Create = function(options, cb) {
        
        getSFConnection(options, function (err, cn, auth) {
            if (err) return cb(err);

            cn
            .sobject(options.Entity)
            .create(options.Details, cb);

            if (auth===jwtFlowAuthToken) cn.logout();
        });
    };

    this.Update = function(options, cb) {
        
        getSFConnection(options, function (err, cn, auth) {
            if (err) return cb(err);

            cn
            .sobject(options.Entity)
            .update(options.Details, cb);

            if (auth===jwtFlowAuthToken) cn.logout();
        });
    };

    this.Upsert = function(options, cb) {
        
        getSFConnection(options, function (err, cn, auth) {
            if (err) return cb(err);

            cn
            .sobject(options.Entity)
            .upsert(options.Details, options.ExternalIdName, cb);

            if (auth===jwtFlowAuthToken) cn.logout();
        });
    };

    this.Delete = function(options, cb) {
        
        getSFConnection(options, function (err, cn, auth) {
            if (err) return cb(err);

            cn
            .sobject(options.Entity)
            .destroy(options.Details, cb);

            if (auth===jwtFlowAuthToken) cn.logout();
        });
    };
};

module.exports = Salesforce;
