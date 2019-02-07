import UIKit
import Web3Swift
import CryptoSwift

enum Asset {
    
    case ERC721(contract: String, tokenId: Int)
    case ERC20(contract: String, amount: Int)
    
    var proxy: EthAddress {
        
        switch self {
        case .ERC721:
            return EthAddress(hex: "0x208e41fb445f1bb1b6780d58356e81405f3e6127")
        case .ERC20:
            return EthAddress(hex: "0x2240Dab907db71e64d3E0dbA4800c83B5C502d4E")
        }
    }
    
    var contract: EthAddress {
        
        switch self {
        case let .ERC721(contract, _):
            return EthAddress(hex: contract)
        case let .ERC20(contract, _):
            return EthAddress(hex: contract)
        }
    }
    
    var amount: Int {
        
        switch self {
        case .ERC721:
            return 1
        case let .ERC20(_, amount):
            return amount
        }
    }
    
    var approve: Int {
        
        switch self {
        case let .ERC721(_, tokenId):
            return tokenId
        case let .ERC20(_, amount):
            return amount
        }
    }
    
    var assetData: RightZeroesPaddedBytes {
        
        switch self {
        case let .ERC721(contract, tokenId):
            
            return RightZeroesPaddedBytes(
                origin: EncodedABIFunction(
                    signature: SimpleString(
                        string: "ERC721Token(address,uint256)"
                    ),
                    parameters: [
                        ABIAddress(
                            address: EthAddress(
                                hex: contract
                            )
                        ),
                        ABIUnsignedNumber(
                            origin: EthNumber(value: tokenId)
                        )
                    ]
                ),
                padding: 32
            )
            
        case let .ERC20(contract, _):
            
            return RightZeroesPaddedBytes(
                origin: EncodedABIFunction(
                    signature: SimpleString(
                        string: "ERC20Token(address)"
                    ),
                    parameters: [
                        ABIAddress(
                            address: EthAddress(
                                hex: contract
                            )
                        )
                    ]
                ),
                padding: 32
            )
        }
    }
}


class Swapper {
    
    let zeroAddress = EthAddress(hex: "0x0000000000000000000000000000000000000000")
    let exchangeContract = EthAddress(hex: "0x4f833a24e1f95d70f028921e27040ca56e09ab0b")
    
    let network: Network
    let maker: EthAddress
    let taker: EthAddress
    
    init(maker: EthAddress, taker: EthAddress, nodeUrl: String) {
        self.maker = maker
        self.taker = taker
        self.network = GethNetwork(url: nodeUrl)
    }
    
    func makeOrderHex(makerAsset: Asset, takerAsset: Asset) throws -> String {
        
        let info = ConcatenatedBytes(
            bytes: try ABITuple(
                parameters: [
                    // makerAddress
                    ABIAddress(
                        address: self.maker
                    ),
                    // takerAddress
                    ABIAddress(
                        address: self.taker
                    ),
                    // feeRecipientAddress
                    ABIAddress(
                        address: self.zeroAddress
                    ),
                    // senderAddress
                    ABIAddress(
                        address: self.zeroAddress
                    ),
                    // makerAssetAmount
                    ABIUnsignedNumber(
                        origin: EthNumber(value: makerAsset.amount)
                    ),
                    // takerAssetAmount
                    ABIUnsignedNumber(
                        origin: EthNumber(value: takerAsset.amount)
                    ),
                    // makerFee
                    ABIUnsignedNumber(
                        origin: EthNumber(value: 0)
                    ),
                    // takerFee
                    ABIUnsignedNumber(
                        origin: EthNumber(value: 0)
                    ),
                    // expirationTimeSeconds
                    ABIUnsignedNumber(
                        origin: EthNumber(value: Int(Date().addingTimeInterval(2592000).timeIntervalSince1970))
                    ),
                    // salt
                    ABIUnsignedNumber(
                        origin: EthNumber(
                            hex: "342FE4E437CADAAB85C56332FD31233C23405877DF8702D7A6C7F84F83DB38FD"
                        )
                    ),
                    // makerAssetData
                    ABIVariableBytes(
                        origin: makerAsset.assetData
                    ),
                    // takerAssetData
                    ABIVariableBytes(
                        origin: takerAsset.assetData
                    )
                ]
                ).heads(offset: 0)
        )
        
        return try info.value().toHexString()
    }
    
    func getOrderHash(orderHex: String) throws -> String {
        
        let getOrderInfoData = BytesFromHexString(
            hex: SimpleString(
                string: "c75e0a81" + "0000000000000000000000000000000000000000000000000000000000000020" + orderHex
            )
        )
        
        let response = EthContractCall(
            network: network,
            contractAddress: exchangeContract,
            functionCall: getOrderInfoData
        )
        
        let hash = DecodedABIFixedBytes(
            abiMessage: ABIMessage(
                message: response
            ),
            length: 32,
            index: 1
        )
        
        return try hash.value().toHexString()
    }
    
    func approve(approverKey: EthPrivateKey, asset: Asset) throws -> String {
        
        let response = try SendRawTransactionProcedure(
            network: network,
            transactionBytes: EthContractCallBytes(
                network: network,
                senderKey: approverKey,
                contractAddress: asset.contract,
                weiAmount: EthNumber(
                    hex: "0x00"
                ),
                functionCall: EncodedABIFunction(
                    signature: SimpleString(
                        string: "approve(address,uint256)"
                    ),
                    parameters: [
                        ABIAddress(
                            address: asset.proxy
                        ),
                        ABIUnsignedNumber(
                            origin: EthNumber(value: asset.approve)
                        )
                    ]
                )
            )
            ).call()
        
        return response["result"].string ?? "Something went wrong"
    }
    
    func signOrder(makerPrivateKey: EthPrivateKey, orderHex: String) throws -> String {
        
        let orderHashHex = try getOrderHash(orderHex: orderHex)
        
        let pk = SECP256k1Signature(
            privateKey: makerPrivateKey,
            message: ConcatenatedBytes(
                bytes: [
                    UTF8StringBytes(
                        string: SimpleString(
                            string: "\u{19}Ethereum Signed Message:\n32"
                        )
                    ),
                    BytesFromHexString(
                        hex: orderHashHex
                    )
                ]
            ),
            hashFunction: SHA3(variant: .keccak256).calculate
        )
        
        let contractSignature = RightZeroesPaddedBytes(
            origin: ConcatenatedBytes(
                bytes: [
                    try EthNumber(value: pk.recoverID().value() + 27),
                    try pk.r(),
                    try pk.s(),
                    SimpleBytes(bytes: [0x03])
                ]
            ),
            padding: 32
        )
        
        return try contractSignature.value().toHexString();
    }
    
    func fillOrder(takerPrivateKey: EthPrivateKey, makerSignatureHex: String, orderHex: String) throws -> String {
        
        let erc721ID = "02571792"
        let erc20ID = "f47261b0"
        
        // Workaround for https://github.com/zeriontech/Web3Swift/issues/176
        
        let magicByte: String
        
        if orderHex.contains(erc721ID) && orderHex.contains(erc20ID) {
            magicByte = "с"
        } else if orderHex.contains(erc721ID) {
            magicByte = "e"
        } else {
            magicByte = "a"
        }
        
        let exchangeData = BytesFromHexString(
            hex: SimpleString(
                string: "b4be83d5" +
                    "0000000000000000000000000000000000000000000000000000000000000060" +
                    "0000000000000000000000000000000000000000000000000000000000000001" +
                    "00000000000000000000000000000000000000000000000000000000000002\(magicByte)0" +
                    orderHex +
                    "0000000000000000000000000000000000000000000000000000000000000042" +
                makerSignatureHex
            )
        )
        
        let exchangeReponse = try SendRawTransactionProcedure(
            network: network,
            transactionBytes: EthContractCallBytes(
                network: network,
                senderKey: takerPrivateKey,
                contractAddress: exchangeContract,
                weiAmount: EthNumber(
                    hex: "0x00"
                ),
                functionCall: exchangeData
            )
            ).call()
        
        return exchangeReponse["result"].string ?? "Something went wrong"
    }
}


let maker = EthAddress(hex: "0x0aD9Fb61a07BAC25625382B63693644497f1B204")
let makerKey = EthPrivateKey(hex: "private_key")

// Crypto Kitty
let makerAsset = Asset.ERC721(contract: "0x06012c8cf97bead5deae237070f9587f8e7a266d", tokenId: 371755)

let taker = EthAddress(hex: "0x4dB6d56Bbb49DD66abC7be5D671fDdF9a5255Cc5")
let takerKey = EthPrivateKey(hex: "private_key")

// DAI
let takerAsset = Asset.ERC20(contract: "0x89d24a6b4ccb1b6faa2625fe562bdd9a23260359", amount: 1000000)

do {
    
    let node = "https://...."
    
    //First device (maker)
    let swapperA = Swapper(maker: maker, taker: taker, nodeUrl: node)
    let txA = try swapperA.approve(approverKey: makerKey, asset: makerAsset)
    print("Approved", txA)
    
    let order = try swapperA.makeOrderHex(makerAsset: makerAsset, takerAsset: takerAsset)
    let signature = try swapperA.signOrder(makerPrivateKey: makerKey, orderHex: order)
    
    // Second device (taker)
    let swapperB = Swapper(maker: maker, taker: taker, nodeUrl: node)
    let txB = try swapperB.approve(approverKey: takerKey, asset: takerAsset)
    print("Approved", txB)
    
    let orderTx = try swapperB.fillOrder(takerPrivateKey: takerKey, makerSignatureHex: signature, orderHex: order)
    print("Order sent", orderTx)
    
} catch {
    
    print(error)
}
