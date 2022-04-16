const express = require('express');
const fileUpload = require('express-fileupload');
const fs = require('fs');
const app = express();
const PORT = 8000;
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const KlayDidClient = require('./did-auth/didAuth.js');
const jwt = require('./lib/jwt.js');

const access = require('./config/access');

app.use(express.static('upload'));
app.use(cors());
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true })); //원래 TRUE였습니다.


// default options
app.use(fileUpload());

app.get('/ping', function(req, res) {
  res.send('pong');
});

app.accessKeyDB = new Map();

app.post('/accessToken', async function(req, res) {
    const didInfo = req.body;
    const uDid = req.body.didInfo;
    const uPubKeyId = req.body.publicKeyId;
    const signature = req.body.signature;
    const data = JSON.stringify(req.body.data);

    const didAuthResult = await KlayDID.didAuth(uDid,uPubKeyId,signature,data)
    
    const isValid = didAuthResult;

    if (!isValid) res.send("Error:The requestor's identity is not confirmed.");

    //accessToken과 endPoint 발급 
    const token = jwt.genJWT()
    console.log(token);
    app.accessKeyDB.set(token.accessToken, token.accessKey);

    //acessPoint
    const accessPoint = {
        'accessToken':token.accessToken,
        'endPoint': access.ENDPOINT+'/claimProp'
    }
    res.send(accessPoint);
      


});

app.post('/claimProp', async function(req, res){
    const accessToken = req.body;
    const accessKey = app.accessKeyDB.get(accessToken);

    const isValid = jwt.verifyJWT(accessToken,accessKey);

    const claimProp = {}; // ui로 띄워야함 
    res.send(claimProp);

});

app.post('/vp', async function(req, res) {  
  console.log('req.files >>>', req.files); // eslint-disable-line

  let vp = req.files.sampleFile;

  let vpPath = __dirname+'/vp/'+vp.name;
  
  vp.mv(vpPath, function(err) {
    if (err) {
      return res.status(500).send(err);
    }

  });
  if (!req.files || Object.keys(req.files).length === 0) {
    res.status(400).send('No vp');
    return;
  }

  let vpJson = require(vpPath);
  console.log(vpJson);

  //vp 검증 시작 

  res.send('success');

});

app.listen(PORT, function() {
  console.log('Express server listening on port ', PORT); // eslint-disable-line
});


