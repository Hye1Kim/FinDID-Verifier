const Caver = require("caver-js");
const Auth = require("./auth");
const secp256k1 = require('secp256k1');
// const {randomBytes} = require('crypto');
// const {Keccak} = require('sha3');
// const hash = new Keccak(256);
// const keccak256 = require('keccak256')


//FinanceDid
module.exports = class FinDIDClient {

  /**
   * @param cfg {
   *  network: blockchain endpoint
   *  regABI: did reg abi path 
   *  regAddr: did reg address
   * }  */
  constructor(cfg) {
    this.caver = new Caver(cfg.network);
    this.auth = new Auth(this.caver);
    this.didReg = new this.caver.contract(cfg.regABI.abi, cfg.regAddr);
    // cfg.regABI.abi erro때문에 임시로 해놈 abi -> https://ko.docs.klaytn.com/getting-started/quick-start/check-the-deployment
  }

  /**@dev get document for did
   * @param dom: did to find document of did in registry
   * @return document
   */
   async getDocument(did) { //fin
    try{
      const dom = await this.didReg.methods.getDocument(did).call();
      return dom; 
    }catch(e){
      console.log(e);
      return {contexts:[]}
    }
  }    




  /**@dev Extract the key to be used in the did document
   * @param dom: Did document
   * @param pubKeyID: ID of the key you are looking for in the document
   * @returns pubKey info
   */
   extractPubKey(dom, pubKeyID){
    const publicKeys = dom.publicKeys;
    for(let i=0; i< publicKeys.length; i++){
      if(publicKeys[i].id ==pubKeyID){
        return publicKeys[i];
      }
    }
  }

 /**
  * @dev 
  * @param signature: 0x{hex string}
  * @param data:  data contained in signature
  * @param pubKey: A public key object{id, keyType, pubKeyData} in document public key list
  * @returns Bool: **/
  isValidSign (signature, data, pubKey){
    if(pubKey.keyType == 'EcdsaSecp256k1RecoveryMethod2020')
        return this._isValid_Secpk1_Recovery2020(signature, data, pubKey.pubKeyData);
    else if(pubKey.keyType == 'EcdsaSecp256k1VerificationKey2019')
        return this._isValid_Secpk1_2019(signature, data, pubKey.pubKeyData);
    return false;
  }

  /**
  * @dev 
  * @param did: did
  * @param pubKeyID: ID of the key you are looking for in the document
  * @param signature: 0x{hex string}
  * @param data:  data contained in signature
  * @returns [isValid, errMsg] **/
  async didAuth(did, pubKeyID, signature, data ){
    const dom = await this.getDocument(did);

    if(dom.contexts.length == 0){
      return [false, 'There is no document for the did in registry'];
    }
        
    const pubKey = this.extractPubKey(dom, pubKeyID);
    if(pubKey == null){
      return [false, 'Public key does not exist in this did document'];
    }

    const isValid = this.isValidSign(signature, data, pubKey);
    if(!isValid){
      return [false, 'Did not valid'];
    }else{
      return [true, ''];
    }
  }


  /**
  * @dev
  * @param data: (string)
  * @param type: 'EcdsaSecp256k1RecoveryMethod2020' or 'EcdsaSecp256k1VerificationKey2019'
  * @param privateKey: hex string ex. 0x (string)
  * @return signature: hex string ex. 0x (string) , VRS: {v:int, r:string, s:stirng}* */ 
  sign(data, type, privateKey){
    if(type == 'EcdsaSecp256k1RecoveryMethod2020'){
      const signObj = this.caver.klay.accounts.sign(data,privateKey);
      const vrsObj = {
        v: parseInt(Number(signObj.v)),
        r: signObj.r,
        s: signObj.s
      }
      return {
        signature: signObj.signature,
        VRS: vrsObj
      };
    }else if(type == 'EcdsaSecp256k1VerificationKey2019'){
      const data32 = hash.update(Buffer.from(data)).digest();
      const pKey = Buffer.from(privateKey.replace("0x",""),'hex');
      const sigObj = secp256k1.ecdsaSign(data32, pKey);
      return {
        signature: '0x'+Buffer.from(sigObj.signature).toString('hex'),
        VRS: null,
      };
    }
    return {
        signature: '0x00',
        VRS: null,
    };
  }


  /**
   * @param statusCode: -n: failed, 1: successful
   * @param msg: result msg 
   */
  _returnMsg(statusCode, msg){
    return {status: statusCode, msg: msg };
  }


  /**
  * @dev internal function
  * @param signature: value signed file metadata with private key (0x{hex}:65byte:module->caver.klay.accounts.sign)
  * @param data: data contained in signature
  * @param pubKey: public key(address) in document (0x{Hex.toLowCase})
  */
  _isValid_Secpk1_Recovery2020(signature, data, pubKeyAddr){
    const signerAddress = this.caver.klay.accounts.recover(data, signature);
    return (pubKeyAddr == signerAddress.toLowerCase());
  }


  /**
  * @dev internal function 
  * @param signature: value signed file metadata with private key (0x{hex}:64byte:module->secp256k1)
  * @param data: data contained in signature
  * @param pubKey: public key in document (0x{Hex})
  */
  _isValid_Secpk1_2019(signature, data, pubKey){
    const pureHexKey = pubKey.replace("0x", "");
    const uint8ArrPubKey = Uint8Array.from(Buffer.from(pureHexKey,'hex'));

    const msg32 = hash.update(Buffer.from(data)).digest();
  
    const pureHexSig = signature.replace("0x","");
    const bytesSig = Buffer.from(pureHexSig,'hex'); 

    return secp256k1.ecdsaVerify(bytesSig, msg32, uint8ArrPubKey);
  }


  /**
     * @param statusCode: -n: failed, 1: successful
     * @param msg: result msg 
     */
  _returnMsg(statusCode, msg){
    return {status: statusCode, msg: msg };
  }


};