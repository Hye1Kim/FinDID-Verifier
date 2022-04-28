const express = require('express');
const fileUpload = require('express-fileupload');
const app = express();
const PORT = 8000;
const bodyParser = require('body-parser');
const cors = require('cors');
const finDID= require('fin-did-auth');/*@dev*/
const jwt = require('access-jwt'); /*@dev*/
const DID_INFO = require('./config/did.js');
const ACCESS = require('./config/access.js');
const ACCOUNT = require('./config/account.js');
const axios = require('axios');

app.use(express.static('upload'));
app.use(cors());
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true })); //원래 TRUE였습니다.


async function _createHash(data){

    const hash = keccak256(Buffer.from(JSON.stringify(data))).toString('hex')
    return hash
  
  }



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
    
    const auth_meta = {
        'verifier' :{
            'did':DID_INFO.SVC_DID,
            'pubKeyID':DID_INFO.SVC_PUBKEY_ID,
            'signature':await (await finDID.sign(DID_INFO.SVC_DID,DID_INFO.SVC_KEYTYPE,ACCOUNT.SVC_PRIVATE_KEY)).signature
        },
        'issuer' : {
            'did':vp.issuerdid,
            'pubKeyID':vp.issuerpkid
        },
        'user': {
            'did':vp.ownerdid,
            'pubKeyID':vp.ownerpkid
        }

    }

    //vp 검증 시작 
    let auth_info = await axios({
       // url: ACCESS.DID_SERVIC+"/auth-info",
       url:'http://203.250.77.154:6000/testServer', 
       method:"post",
       data: auth_meta //json
    });
    auth_info = auth_info.data
    console.log(auth_info); //auth_info.data

    let ciid = await axios({
        // url: ACCESS.DID_SERVIC+"/auth-info",
        url: ACCESS.VC_STORAGE+'/', 
        method:"post",
        data: {'cid':vp.cid} //json
     });
     ciid = ciid.data
     console.log(ciid); //auth_info.data

    //1) vp signature 검증
    const vp1 = vp;
    const vpSig = vp1.signature;
    delete vp1.signature;
    const isValid_vpSig = await finDID.didAuth({ 'keyType':auth_info.user.keyType,'pubKeyData' :auth_info.user.pubKey},vpSig,JSON.stringify(vp1));
    if(!isValid_vpSig) res.send('Not Valid VP Signature!');

    //2) vp id 
    const vp2;
    const pid = vp.pid;
    delete vp2.pid;
    const isValid_pid = (pid == await _createHash(vp2));
    if(!isValid_pid) res.send("Not valid VP ID");

    //3) claim 
    const claims = vp.claim
    var claim = Object.keys(claims); //key
    const infos = vp.info
    var info = Object.keys(infos); //key
    for(i=0;i<claim.length;i++){
        var signData = claims[claim[i]]+ ciid; //value + ciid
        const isValid_claim = await finDID.didAuth({ 'keyType':auth_info.issuer.keyType,'pubKeyData' :auth_info.issuer.pubKey},infos[info[i]],JSON.stringify(signData));
        if(!isValid_claim) res.send('Not Valid claim');
    }

    res.send('success');

});

app.listen(PORT, function() {
  console.log('Express server listening on port ', PORT); // eslint-disable-line
});





/* vp sample

req>>  {
  vp: {
    pid: 'bd83e169c25b0e3c0f9dbeefb446ec5e1bc571b7b92666225363e076297e4d48',
    cid: 'eb6f296624d41eafb16cf14d15574b7a39462d380e5cfe12c05e7480ce8a7a74',
    issuerdid: '0x',
    issuerpkid: '0x',
    ownerdid: 'did:kt:76f021c05fc4aa8e94a94078787a4e901bab9e6b4381748dd4f8e8ab4274febf',
    ownerpkid: 'did:kt:76f021c05fc4aa8e94a94078787a4e901bab9e6b4381748dd4f8e8ab4274febf#key-1',
    claims: {
      name: '김혜원',
      address: '울산광역시 남구 대학로 93',
      email: 'alsldjcjstk@xx.com'
    },
    infos: {},
    valid: '2022-04-22T06:59:53.452Z',
    signature: '0xfdbd5d6312601479ec81b51ad45d18c53d48f299c3842929edf65cb45fed4ea4595e8114ef647877d4e9f1f55259c1a3fb9c9caef90738c0b4c15c53ff6101ce1c'
  }
}

*/