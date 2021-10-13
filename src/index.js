const { pubToAddress } = require('ethereumjs-util')
    , { bip32 } = require('bitcoinjs-lib')
    , ec = require('elliptic').ec('secp256k1')
    , bip39 = require('bip39')
    , BIP84 = require('bip84')

function fromMnemonic(mnemonic, password, isTestnet) {
  BIP84.fromMnemonic.call(this, mnemonic, password, isTestnet, 60)
}

fromMnemonic.prototype = Object.create(BIP84.fromMnemonic.prototype)

function fromZPrv(zprv) {
  BIP84.fromZPrv.call(this, zprv)
}

fromZPrv.prototype = Object.create(BIP84.fromZPrv.prototype)

fromZPrv.prototype.getPrivateKey = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubKey = bip32.fromBase58(this.zprv, this.network).derive(change).derive(index).privateKey

  return pubKey.toString('hex')
}

fromZPrv.prototype.getPublicKey = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubKey = bip32.fromBase58(this.zprv, this.network).derive(change).derive(index).publicKey

  return pubKey.toString('hex')
}

fromZPrv.prototype.getAddress = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubKey = bip32.fromBase58(this.zprv, this.network).derive(change).derive(index).publicKey
    , address = pubToAddress(bip32PublicToEthereumPublic(pubKey))

  return `0x${address.toString('hex')}`
}

function fromZPub(zpub) {
  BIP84.fromZPub.call(this, zpub)
}

fromZPub.prototype = Object.create(BIP84.fromZPub.prototype)

fromZPub.prototype.getPublicKey = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubKey = bip32.fromBase58(this.zpub, this.network).derive(change).derive(index).publicKey

  return pubKey.toString('hex')
}


fromZPub.prototype.getAddress = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubKey = bip32.fromBase58(this.zpub, this.network).derive(change).derive(index).publicKey
    , address = pubToAddress(bip32PublicToEthereumPublic(pubKey))

  return `0x${address.toString('hex')}`
}

const padTo32 = function(msg) {
  while (msg.length < 32) {
    msg = Buffer.concat([Buffer.from([0]), msg])
  }

  if (msg.length !== 32) {
    throw new Error(`invalid key length: ${msg.length}`)
  }

  return msg
}

const bip32PublicToEthereumPublic = function(pubKey) {
  let key = ec.keyFromPublic(pubKey).getPublic().toJSON()

  return Buffer.concat([padTo32(Buffer.from(key[0].toArray())), padTo32(Buffer.from(key[1].toArray()))])
}

module.exports = {
  generateMnemonic: bip39.generateMnemonic,
  entropyToMnemonic: bip39.entropyToMnemonic,
  fromMnemonic: fromMnemonic,
  fromZPrv: fromZPrv,
  fromZPub: fromZPub
}
