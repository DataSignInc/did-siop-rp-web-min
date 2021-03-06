//********************************************************************
//* file : server.js
//* https:localhost:5001
//*
//********************************************************************

const IP = "192.168.0.6"

const express = require('express');
const http = require('http');
const DID_SIOP = require('did-siop');

var app = express();

app.use('/', express.static(__dirname + '/'));

app.get('/', function (req, res) {
    res.redirect('/index');
});

const siop_rp_promise = DID_SIOP.RP.getRP(
    `http://${IP}:5001/home`, // RP's redirect_uri
    'did:web:assets-datasign.s3-ap-northeast-1.amazonaws.com:siop-test:rp', // RP's did
    {
        "authorization_endpoint": "openid:",
        "issuer": "https://self-issued.me/v2",
        "response_types_supported":
            ["id_token"],
        "scopes_supported":
            ["openid", "profile", "email", "address", "phone"],
        "subject_types_supported":
            ["pairwise"],
        "subject_identifier_types_supported":
            ["did:web:", "did:ion:"],
        "id_token_signing_alg_values_supported": 
            ["ES256K-R", "EdDSA", "RS256"],
        "request_object_signing_alg_values_supported":
            ["ES256", "ES256K"],
        "redirect_uris": [`http://${IP}:5001/home`],
        "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
        // "id_token_encrypted_response_alg": "", 
        // "id_token_encrypted_response_enc": "",
        "did": 'did:web:assets-datasign.s3-ap-northeast-1.amazonaws.com:siop-test:rp'
    }
)

app.get('/index', indexPage);
// app.get('/home',homePage);
app.get('/get_request_object', getRequestObject);
app.get('/start', startSignIn);
app.get('/home', homePage);
app.get('/validate', processJWT);

function indexPage(req, res, next) {
    res.append("Cache-Control", "no-cache")
    console.log("indexPage Invoked");
    res.sendFile('index.html', { root: __dirname + '/' });
}

function homePage(req, res, next) {
    res.append("Cache-Control", "no-cache")
    console.log("homePage Invoked");
    res.sendFile('home.html', { root: __dirname + '/' });
}

async function startSignIn(req, res, next) {
    res.append("Cache-Control", "no-cache")
    console.log("startSignIn() Invoked");
    var requestObject;
    requestObject = await generateRequestObject();
    res.redirect(302, requestObject);
}

async function getRequestObject(req, res, next) {
    res.append("Cache-Control", "no-cache")
    console.log("getRequestObject Invoked");
    var requestObject;
    requestObject = await generateRequestObject();
    res.send(JSON.stringify({ 'reqObj': requestObject }));
}

async function generateRequestObject() {
    console.log('startProcess');
    var request;

    siop_rp = await siop_rp_promise;
    console.log('Got RP instance ....');
    siop_rp.addSigningParams(
        '8329a21d9ce86fa08e75354469fb8d78834f126415d5b00eef55c2f587f3abca', // Private key
        'did:web:assets-datasign.s3-ap-northeast-1.amazonaws.com:siop-test:rp#controller', // Corresponding authentication method in RP's did document (to be used as kid value for key)
        DID_SIOP.KEY_FORMATS.HEX, //Format in which the key is supplied. List of values is given below
        DID_SIOP.ALGORITHMS['ES256K-R']
    );

    console.log('RP SigningParams added ...');
    request = await siop_rp.generateRequest({redirect_uri: `http://${IP}:5001/home`, kid: 'did:ethr:0xA51E8281c201cd6Ed488C3701882A44B1871DAd6#controller'});

    console.log('Request generated ...', request);
    return request;
}

async function processJWT(req, res, next) {
    // console.log(req)
    const { id_token: idToken } = req.query
    siop_rp = await siop_rp_promise;
    siop_rp.addSigningParams(
        '8329a21d9ce86fa08e75354469fb8d78834f126415d5b00eef55c2f587f3abca', // Private key
        'did:web:assets-datasign.s3-ap-northeast-1.amazonaws.com:siop-test:rp#controller', // Corresponding authentication method in RP's did document (to be used as kid value for key)
        DID_SIOP.KEY_FORMATS.HEX, //Format in which the key is supplied. List of values is given below
        DID_SIOP.ALGORITHMS['ES256K']
    );

    try {
        res.append("Cache-Control", "no-cache")
        console.log('Response validated...');
        let valid = await siop_rp.validateResponse(idToken)
        console.log("success");
        console.log('Validated response', valid);
        if (valid) {
            res.send({idToken: valid, status: "Valid"})
        } else {
            res.send({ status: "something" })
        }
    } catch (error) {
        res.status(401).send({ status: error.message });
        console.log("error sent")
        console.log(error)
    }
}


const port = process.env.PORT || 5001;
const server = http.createServer(app);
server.listen(port, () => {
    console.log('Listening on ', port);
    console.log(server.address().address)
});
