//
//  ViewController.swift
//  EncryptionAndDecryption
//
//  Created by Alphonsa Varghese on 29/06/23.
//

import UIKit
import CommonCrypto

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        
        // Usage example
//        let originalString = "2023-06-28 17:41 [DEBUG] [tag : testing] [AV : 1.0] [OS : 16.2] [ContentView.swift]:34 body : Tapped on listview cell 12"
        let originalString = "2023-06-26 14:34 [AV : 2.0] [OS : 16.2.0] [UUID : 61249068-ADB8-47FC-AC6D-AD2343118B14] [DEBUG] [ViewController.swift] : viewDidLoad() [Line 16]: Testing Log Level debug"
        let encryptionKey = "abcdefghijklmnop"
        let initializationVector = "1234567890abcdef"

        let encryptedString = encryptString(string: originalString, key: encryptionKey, iv: initializationVector)
        print("Encrypted: \(encryptedString ?? "Encryption failed")")

        let decryptedString = decryptString(string: encryptedString ?? "", key: encryptionKey, iv: initializationVector)
        print("Decrypted: \(decryptedString ?? "Decryption failed")")

    }



    func encryptString(string: String, key: String, iv: String) -> String? {
        guard let data = string.data(using: .utf8) else { return nil }
        
        let keyData = key.data(using: .utf8)!
        let ivData = iv.data(using: .utf8)!
        
        let cryptLength = size_t(data.count + kCCBlockSizeAES128)
        var cryptData = Data(count: cryptLength)
        
        let keyLength = size_t(kCCKeySizeAES128)
        let options = CCOptions(kCCOptionPKCS7Padding)
        
        var numBytesEncrypted: size_t = 0
        
        let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                ivData.withUnsafeBytes { ivBytes in
                    keyData.withUnsafeBytes { keyBytes in
                        CCCrypt(CCOperation(kCCEncrypt),
                                CCAlgorithm(kCCAlgorithmAES),
                                options,
                                keyBytes.baseAddress,
                                keyLength,
                                ivBytes.baseAddress,
                                dataBytes.baseAddress,
                                data.count,
                                cryptBytes.baseAddress,
                                cryptLength,
                                &numBytesEncrypted)
                    }
                }
            }
        }
        
        guard cryptStatus == kCCSuccess else { return nil }
        
        cryptData.removeSubrange(numBytesEncrypted..<cryptData.count)
        
        return cryptData.base64EncodedString()
    }

    func decryptString(string: String, key: String, iv: String) -> String? {
        guard let data = Data(base64Encoded: string) else { return nil }
        
        let keyData = key.data(using: .utf8)!
        let ivData = iv.data(using: .utf8)!
        
        let cryptLength = size_t(data.count + kCCBlockSizeAES128)
        var cryptData = Data(count: cryptLength)
        
        let keyLength = size_t(kCCKeySizeAES128)
        let options = CCOptions(kCCOptionPKCS7Padding)
        
        var numBytesDecrypted: size_t = 0
        
        let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                ivData.withUnsafeBytes { ivBytes in
                    keyData.withUnsafeBytes { keyBytes in
                        CCCrypt(CCOperation(kCCDecrypt),
                                CCAlgorithm(kCCAlgorithmAES),
                                options,
                                keyBytes.baseAddress,
                                keyLength,
                                ivBytes.baseAddress,
                                dataBytes.baseAddress,
                                data.count,
                                cryptBytes.baseAddress,
                                cryptLength,
                                &numBytesDecrypted)
                    }
                }
            }
        }
        
        guard cryptStatus == kCCSuccess else { return nil }
        
        cryptData.removeSubrange(numBytesDecrypted..<cryptData.count)
        
        return String(data: cryptData, encoding: .utf8)
    }


}

