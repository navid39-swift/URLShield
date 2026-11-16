//
//  ModelUpdater.swift
//  URLShield1
//
//  Downloads a newer model + lists, and installs them only if:
//   1. the manifest is signed with Navid's private key (Ed25519),
//   2. every file matches its SHA-256 hash from the manifest,
//   3. the new model compiles and reproduces the expected scores (self-test).
//  Nothing about the user is ever uploaded: the app only downloads files.
//

import CoreML
import CryptoKit
import Foundation

struct UpdateManifest: Codable {
    struct FileEntry: Codable {
        let name: String
        let sha256: String
    }
    struct SelfTest: Codable {
        let host: String
        let pPhishing: Double
    }

    let version: Int
    let featureSchema: String
    let files: [FileEntry]
    let selfTests: [SelfTest]
    let notes: String?
}

enum ModelUpdaterError: Error {
    case notConfigured
    case badSignature
    case wrongSchema
    case missingFile(String)
    case hashMismatch(String)
    case selfTestFailed(String)
}

enum ModelUpdater {

    // MARK: Configuration (fill in after running make_signing_key.py)

    /// Folder where the update files are published, ending with "/".
    static let baseURL = URL(string: "https://navid39-swift.github.io/urlshield-updates/")!

    /// Base64 public key printed by make_signing_key.py.
    static let publicKeyBase64 = "5I6L+wWJFQzDjVzFmyJhgQ1PCFMQ06nM2c5NkWQWs18="

    private static let lastCheckKey = "lastModelUpdateCheck"

    enum Outcome: Equatable {
        case upToDate
        case updated(Int)
        case notConfigured
    }

    static var isConfigured: Bool {
        !publicKeyBase64.hasPrefix("PASTE") && !baseURL.absoluteString.contains("YOUR-GITHUB-USERNAME")
    }

    // MARK: Checking

    /// Automatic check, at most once a day. Errors are ignored silently.
    static func checkIfDue() async {
        guard isConfigured, !ModelStore.isRunningTests else { return }
        let defaults = UserDefaults.standard
        if let last = defaults.object(forKey: lastCheckKey) as? Date,
           Date().timeIntervalSince(last) < 24 * 3600 {
            return
        }
        defaults.set(Date(), forKey: lastCheckKey)
        _ = try? await check()
    }

    /// Manual check (About screen).
    static func check() async throws -> Outcome {
        guard isConfigured else { return .notConfigured }

        let session = URLSession(configuration: .ephemeral)
        // No manifest published yet: nothing to update.
        guard let manifestData = try await download("manifest.json", session: session, allowMissing: true) else {
            return .upToDate
        }
        guard let signatureData = try await download("manifest.sig", session: session, allowMissing: false) else {
            throw ModelUpdaterError.badSignature
        }

        try verifySignature(manifest: manifestData, signature: signatureData)

        let manifest = try JSONDecoder().decode(UpdateManifest.self, from: manifestData)
        guard manifest.featureSchema == ModelStore.featureSchema else { throw ModelUpdaterError.wrongSchema }
        guard manifest.version > ModelStore.currentVersion else { return .upToDate }

        try await install(manifest, session: session)
        return .updated(manifest.version)
    }

    /// Downloads one file. Returns nil for 404 when allowMissing, throws for other errors.
    private static func download(_ name: String, session: URLSession, allowMissing: Bool) async throws -> Data? {
        let (data, response) = try await session.data(from: baseURL.appendingPathComponent(name))
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        if status == 404 && allowMissing { return nil }
        guard status == 200 else { throw ModelUpdaterError.missingFile(name) }
        return data
    }

    static func verifySignature(manifest: Data, signature: Data) throws {
        guard let keyData = Data(base64Encoded: publicKeyBase64),
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: keyData),
              let text = String(data: signature, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
              let signatureBytes = Data(base64Encoded: text),
              key.isValidSignature(signatureBytes, for: manifest)
        else { throw ModelUpdaterError.badSignature }
    }

    // MARK: Installing

    private static func install(_ manifest: UpdateManifest, session: URLSession) async throws {
        guard let root = ModelStore.rootDirectory else { throw CocoaError(.fileNoSuchFile) }
        let fm = FileManager.default
        try fm.createDirectory(at: root, withIntermediateDirectories: true)

        let staging = root.appendingPathComponent("staging-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: staging, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: staging) }

        let modelFile = "\(ModelStore.modelName).mlmodel"
        let required = [modelFile] + ModelStore.jsonResources.map { "\($0).json" }
        for name in required where !manifest.files.contains(where: { $0.name == name }) {
            throw ModelUpdaterError.missingFile(name)
        }

        // 1. Download and verify every file
        for file in manifest.files {
            guard required.contains(file.name) else { continue }   // ignore unknown files
            guard let data = try await download(file.name, session: session, allowMissing: false) else {
                throw ModelUpdaterError.missingFile(file.name)
            }
            let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            guard hash == file.sha256.lowercased() else { throw ModelUpdaterError.hashMismatch(file.name) }
            try data.write(to: staging.appendingPathComponent(file.name))
        }

        // 2. Compile the model on the device
        let compiled = try await MLModel.compileModel(at: staging.appendingPathComponent(modelFile))
        let compiledTarget = staging.appendingPathComponent("\(ModelStore.modelName).mlmodelc")
        try fm.moveItem(at: compiled, to: compiledTarget)
        try? fm.removeItem(at: staging.appendingPathComponent(modelFile))

        // 3. Self-test: the new model must give the scores Python computed
        let predictor = try HostPhishingPredictor(
            modelURL: compiledTarget,
            tldRatesURL: staging.appendingPathComponent("tld_rates.json")
        )
        for test in manifest.selfTests {
            let p = try predictor.predict(host: test.host).phishingProbability
            guard abs(p - test.pPhishing) < 0.001 else { throw ModelUpdaterError.selfTestFailed(test.host) }
        }

        // 4. Activate: move into place, then switch the pointer
        let folderName = "v\(manifest.version)"
        let finalFolder = root.appendingPathComponent(folderName, isDirectory: true)
        if fm.fileExists(atPath: finalFolder.path) { try fm.removeItem(at: finalFolder) }
        try fm.moveItem(at: staging, to: finalFolder)

        let pointer = ModelStore.ActiveUpdate(version: manifest.version, folder: folderName, installedAt: Date())
        try JSONEncoder().encode(pointer).write(to: root.appendingPathComponent("active.json"), options: .atomic)

        // 5. Remove older downloaded versions
        let contents = (try? fm.contentsOfDirectory(atPath: root.path)) ?? []
        for name in contents where name.hasPrefix("v") && name != folderName {
            try? fm.removeItem(at: root.appendingPathComponent(name))
        }
    }
}
