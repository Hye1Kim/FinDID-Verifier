const express = require('express');
const fileUpload = require('express-fileupload');
const app = express();
const PORT = 8000;
const bodyParser = require('body-parser');
const cors = require('cors');
const finDID= require('fin-did-auth');/*@dev*/
const jwt = require('access-jwt'); /*@dev*/

const ACCESS = require('./config/access');

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
    console.log('########/accessToken#######');
    console.log(req.body);
    const didInfo = req.body;
    const uDid = didInfo.did;
    const uPubKeyId = didInfo.publicKeyID;
    const signature = didInfo.signature;
    const data = JSON.stringify(didInfo.did);
    const exp = '60000ms';

    const authInfo = {
        'pubKey': {'keyType':didInfo.keyType,'pubKeyData' :didInfo.publicKey},
        'signature':signature,
        

    }

    const didAuthResult = await finDID.didAuth({ 'keyType':didInfo.keyType,'pubKeyData' :didInfo.publicKey},signature,data)
    
    const isValid = didAuthResult;
    console.log(didAuthResult);

    if (!isValid) res.send("Error : The requestor's identity is not confirmed.");

    //accessToken과 endPoint 발급 
    const token = await jwt.genJWT(exp,didInfo)
    console.log(token);
    if(!token) res.send("Error : jwt not generated.");
    
    app.accessKeyDB.set(token.accessToken, token.accessKey);

    const accessPoint = {
        'accessToken':token.accessToken,
        'endPoint': ACCESS.VERIFIER+'/claimProp'
    }
    res.send(accessPoint);
      


});

app.post('/claimProp', async function(req, res){
    console.log('########/claimProp#######');
    console.log(req.body);
    const accessToken = req.body.accessToken; //accessToken
    const accessKey = app.accessKeyDB.get(accessToken);

    const isValid = await jwt.verifyJWT(accessToken,accessKey);
    if(!isValid) res.send('Not Valid Access Token');

    const claimProp = {}; // ui로 띄워야함
    const result = {
        'claimProp':'알아서 보내쇼',
        'endPoint': ACCESS.VERIFIER+'/vp'
    }
    res.send(result);

});

app.post('/vp', async function(req, res) {
  console.log('########/vp#######');
  console.log('req>> ' ,req.body);

  const vp = req.body.vp
  
  //vp 검증 시작 

  //1) vp signature 검증
  const vpSig = vp.signature;



  res.send('success');

});

app.listen(PORT, function() {
  console.log('Express server listening on port ', PORT); // eslint-disable-line
});


