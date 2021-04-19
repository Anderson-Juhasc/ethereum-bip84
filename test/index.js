const { fromMnemonic, fromZPrv, fromZPub } = require('../src/index')

var mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
var root = new fromMnemonic(mnemonic)
var child0 = root.deriveAccount(0)

console.log('mnemonic:', mnemonic)
console.log('rootpriv:', root.getRootPrivateKey())
console.log('rootpub:', root.getRootPublicKey())
console.log('\n');

var account0 = new fromZPrv(child0)

console.log("Account 0, root = m/84'/60'/0'");
console.log('Account 0 zprv:', account0.getAccountPrvKey())
console.log('Account 0 zpub:', account0.getAccountPubKey())
console.log('\n');

console.log("Account 0, first receiving address = m/84'/60'/0'/0/0");
console.log('Prvkey:', account0.getPrvKey(0))
console.log('Pubkey:', account0.getPubKey(0))
console.log('Address:', account0.getAddress(0))
console.log('\n');

console.log("Account 0, second receiving address = m/84'/60'/0'/0/1");
console.log('Prvkey:', account0.getPrvKey(1))
console.log('Pubkey:', account0.getPubKey(1))
console.log('Address:', account0.getAddress(1))
console.log('\n');

console.log("Account 0, first change address = m/84'/60'/0'/1/0");
console.log('Prvkey:', account0.getPrvKey(0, true))
console.log('Pubkey:', account0.getPubKey(0, true))
console.log('Address:', account0.getAddress(0, true))
console.log('\n');

var zpub = account0.getAccountPubKey()
var account1 = new fromZPub(zpub)

console.log("Account 1, root = m/84'/60'/0'");
console.log('Account 1 zpub:', account1.getAccountPubKey());
console.log('\n');

console.log("Account 1, first receiving address = m/84'/60'/0'/0/0");
console.log('Pubkey:', account1.getPubKey(0))
console.log('Address:', account1.getAddress(0))
console.log('\n');

console.log("Account 1, second receiving address = m/84'/60'/0'/0/1");
console.log('Pubkey:', account1.getPubKey(1))
console.log('Address:', account1.getAddress(1))
console.log('\n');

console.log("Account 1, first change address = m/84'/60'/0'/1/0");
console.log('Pubkey:', account1.getPubKey(0, true))
console.log('Address:', account1.getAddress(0, true))
console.log('\n');

console.log("Account 1, second change address = m/84'/60'/0'/1/1");
console.log('Pubkey:', account1.getPubKey(1, true))
console.log('Address:', account1.getAddress(1, true))
console.log('\n');
