const jwt  = require('jsonwebtoken');
const crypto = require('crypto');


 /**
  * @dev 
  * @param exp: ex) "60000ms"
  * @param payload: value
  * @returns token: {accessToken : generated JWT, accessKey : random secretKey} **/
const genJWT = async function (exp,payload){
    const accessKey = await crypto.randomBytes(64).toString('hex'); //secretKey
    //var exp = auctionMeta.timestamp+'ms';
    var exp = '60000ms'  
    const options = {
        "algorithm": "HS256",
        "expiresIn": exp
    };
    
    try{
        const accessToken = await jwt.sign(payload,accessKey,options);
        const token = {
            'accessToken': accessToken,
            'accessKey': accessKey
        }
        return token;

    }catch(err){
        console.log('error: The jwt was not generated...',err);
        return false;
    }
}

 /**
  * @dev 
  * @param accessToken: generated JWT
  * @param accessKey: random secretKey to verify
  * @returns bool **/
const verifyJWT = async function (accessToken, accessKey){
    try{
        const result = await jwt.verify(accessToken, accessKey);   
        return result ;     
    }catch(err){
        console.log(err);
        return false;

    };
   
}

module.exports.genJWT = genJWT;
module.exports.verifyJWT = verifyJWT;
