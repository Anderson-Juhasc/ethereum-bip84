const { pubToAddress } = require('ethereumjs-util')
    , { bip32, networks } = require('bitcoinjs-lib')
    , b58 = require('bs58check')
    , ec = require('elliptic').ec('secp256k1')
    , bip39 = require('bip39')
    , pubTypes = { zprv: '04b2430c', zpub: '04b24746' }

const padTo32 = function(msg) {
  while (msg.length < 32) {
    msg = Buffer.concat([new Buffer([0]), msg])
  }

  if (msg.length !== 32) {
    throw new Error(`invalid key length: ${msg.length}`)
  }

  return msg
}

const bip32PublicToEthereumPublic = function(pubKey) {
  let key = ec.keyFromPublic(pubKey).getPublic().toJSON();

  return Buffer.concat([padTo32(new Buffer(key[0].toArray())), padTo32(new Buffer(key[1].toArray()))]);
}

const toHD = function (zprv, network) {
  let payload = b58.decode(zprv)
    , version = payload.slice(0, 4)
    , key = payload.slice(4)
    , buf = Buffer.allocUnsafe(4)
    , buffer

  buf.writeInt32BE(network, 0)
  buffer = Buffer.concat([buf, key])

  return b58.encode(buffer)
}

const b58Encode = function(pub, data) {
  let payload = b58.decode(pub)
    , key = payload.slice(4)

  return b58.encode(Buffer.concat([Buffer.from(data,'hex'), key]))
}

function fromMnemonic(mnemonic, password) {
  this.seed = bip39.mnemonicToSeedSync(mnemonic, password ? password : '')
}

fromMnemonic.prototype.getRootPrivateKey = function() {
  const prv = bip32.fromSeed(this.seed).toBase58()
      , masterKey = b58Encode(prv, pubTypes.zprv)

  return masterKey
}

fromMnemonic.prototype.getRootPublicKey = function() {
  const pub = bip32.fromSeed(this.seed).neutered().toBase58()
      , masterKey = b58Encode(pub, pubTypes.zpub)

  return masterKey
}

fromMnemonic.prototype.deriveAccount = function(index, changePurpose) {
  const purpose = changePurpose || 84
      , keypath = `m/${purpose}'/${60}'/${index}'`
      , account = bip32.fromSeed(this.seed).derivePath(keypath).toBase58()

  return account
}

function fromZPrv(zprv) {
  this.zprv = toHD(zprv, networks.bitcoin.bip32.private)
}

fromZPrv.prototype.getAccountPrvKey = function() { 
  let prv = bip32.fromBase58(this.zprv).toBase58()
    , masterKey = b58Encode(prv, pubTypes.zprv)

	return masterKey
}

fromZPrv.prototype.getAccountPubKey = function() {
  let pub = bip32.fromBase58(this.zprv).neutered().toBase58()
    , masterKey = b58Encode(pub, pubTypes.zpub)

  return masterKey
}

fromZPrv.prototype.getPrvKey = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubKey = bip32.fromBase58(this.zprv.toString()).derive(change).derive(index).privateKey

  return pubKey.toString('hex')
}

fromZPrv.prototype.getPubKey = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubKey = bip32.fromBase58(this.zprv.toString()).derive(change).derive(index).publicKey

  return pubKey.toString('hex')
}

fromZPrv.prototype.getAddress = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubKey = bip32.fromBase58(this.zprv.toString()).derive(change).derive(index).publicKey
    , address = pubToAddress(bip32PublicToEthereumPublic(pubKey))

  return `0x${address.toString('hex')}`;
}

function fromZPub(zpub) {
  this.zpub = toHD(zpub, networks.bitcoin.bip32.public)
}

fromZPub.prototype.getAccountPubKey = function() {
  let pub = bip32.fromBase58(this.zpub).neutered().toBase58()
    , masterKey = b58Encode(pub, pubTypes.zpub)

  return masterKey
}

fromZPub.prototype.getPubKey = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubKey = bip32.fromBase58(this.zpub).derive(change).derive(index).publicKey

  return pubKey.toString('hex')
}


fromZPub.prototype.getAddress = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubKey = bip32.fromBase58(this.zpub).derive(change).derive(index).publicKey
    , address = pubToAddress(bip32PublicToEthereumPublic(pubKey))

  return `0x${address.toString('hex')}`
}

module.exports = {
  generateMnemonic: bip39.generateMnemonic,
  entropyToMnemonic: bip39.entropyToMnemonic,
  fromMnemonic: fromMnemonic,
  fromZPrv: fromZPrv,
  fromZPub: fromZPub
}
