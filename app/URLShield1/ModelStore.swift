//
//  ModelStore.swift
//  URLShield1
//
//  Decides which model and lists are used: a verified downloaded update
//  (if one is installed) or the version built into the app.
//  Shared by the app, the Share extension and the SMS filter.
//

import Foundation

enum ModelStore {
    static let appGroupID = "group.com.navidzare.URLShield1"
    /// Version of the model shipped inside the app.
    static let bundledVersion = 2
    /// Updates must use the same 10 input features as this app version.
    static let featureSchema = "host-v1"
    static let modelName = "URLShieldHost"
    static let jsonResources = ["tld_rates", "allowlist", "special_hosts"]

    struct ActiveUpdate: Codable {
        let version: Int
        let folder: String
        let installedAt: Date
    }

    /// Tests always use the built-in model, so their expected values stay valid.
    static var isRunningTests: Bool {
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
    }

    /// The shared App Group folder if available (so extensions see updates too),
    /// otherwise the app's own Application Support folder.
    static var rootDirectory: URL? {
        let fm = FileManager.default
        let base = fm.containerURL(forSecurityApplicationGroupIdentifier: appGroupID)
            ?? fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
        return base?.appendingPathComponent("ModelUpdates", isDirectory: true)
    }

    static var pointerURL: URL? {
        rootDirectory?.appendingPathComponent("active.json")
    }

    static func folderURL(for update: ActiveUpdate) -> URL? {
        rootDirectory?.appendingPathComponent(update.folder, isDirectory: true)
    }

    /// The installed update, only if it is newer than the built-in model and complete.
    static func activeUpdate() -> ActiveUpdate? {
        guard !isRunningTests,
              let pointerURL,
              let data = try? Data(contentsOf: pointerURL),
              let update = try? JSONDecoder().decode(ActiveUpdate.self, from: data),
              update.version > bundledVersion,
              let folder = folderURL(for: update),
              FileManager.default.fileExists(atPath: folder.appendingPathComponent("\(modelName).mlmodelc").path)
        else { return nil }
        return update
    }

    static var currentVersion: Int {
        activeUpdate()?.version ?? bundledVersion
    }

    /// Compiled model of the active update, or nil to use the built-in one.
    static var activeModelURL: URL? {
        activeUpdate()
            .flatMap { folderURL(for: $0) }?
            .appendingPathComponent("\(modelName).mlmodelc")
    }

    /// A JSON list from the active update, or the built-in one.
    static func url(forResource name: String, withExtension ext: String, fallback bundle: Bundle = .main) -> URL? {
        if let folder = activeUpdate().flatMap({ folderURL(for: $0) }) {
            let candidate = folder.appendingPathComponent("\(name).\(ext)")
            if FileManager.default.fileExists(atPath: candidate.path) {
                return candidate
            }
        }
        return bundle.url(forResource: name, withExtension: ext)
    }
}
