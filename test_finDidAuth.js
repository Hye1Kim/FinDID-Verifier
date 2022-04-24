//함수 하나씩 실행해보는 서버 없는 테스트 클라이언트 

const finDID = require('fin-did-auth');
const ACCOUNT = require('./config/account.js');


/************************* interface *******************************/


async function test() { //Restful API 에서 하는 역할(임시)



  /* did sign */
  const privateKey = ACCOUNT.YOUNG_PRIVATE_KEY;
  const data = 'did:kt:76f021c05fc4aa8e94a94078787a4e901bab9e6b4381748dd4f8e8ab4274febf';
  const JsonData = JSON.stringify(data);
  const keyType = 'EcdsaSecp256k1RecoveryMethod2020'
  const signature = await finDID.sign(JsonData, keyType, privateKey)
  console.log(signature.signature);


  /* did auth */
  // const authInfo = { 
  //   'did':'did:kt:5180c3861260fadec4c1468660530fca1b21a48a048d65c27ecbeae5037f358c', 
  //   'pubKeyID':'did:kt:5180c3861260fadec4c1468660530fca1b21a48a048d65c27ecbeae5037f358c#key-1',
  //   'pubKey':{'keyType':'EcdsaSecp256k1RecoveryMethod2020','pubKeyData':ACCOUNT.ADDRESS}, 
  //   'signature': '0x105894aac9b9b1af4048c482df7f1c5c7106ea8dee4884522b5ceaefdc74f0b50f4affecc8c48fa37bc001a7e97d4a115440466ca5209ffc8f6f67ea0ed3b7521b' , 
  //   'data':JsonData
  // };

  const authInfo = {
    'did': 'did:kt:76f021c05fc4aa8e94a94078787a4e901bab9e6b4381748dd4f8e8ab4274febf',
    'pubKey': {'pubKeyData': '0x180150aa48b9ebae77e569eacc31c807f81d2031',
    'keyType': 'EcdsaSecp256k1RecoveryMethod2020'},
    'signature': '0x5708d3f9f756e65a836832b53c571a86c576bdb374f280535058366f9bae9dac46476678c5c9b327093055da2ef44b013614afb762723db4a5a6e2f3a8128bdd1c'
  }


  const isValid = await finDID.didAuth(authInfo.pubKey,authInfo.signature,JsonData);
  console.log(isValid);

}

test();