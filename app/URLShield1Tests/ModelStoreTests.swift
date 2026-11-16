//
//  ModelStoreTests.swift
//  URLShield1Tests
//

import Foundation
import Testing
@testable import URLShield1

@MainActor
struct ModelStoreTests {

    @Test func testsAlwaysUseBuiltInModel() {
        #expect(ModelStore.isRunningTests)
        #expect(ModelStore.activeUpdate() == nil)
        #expect(ModelStore.currentVersion == ModelStore.bundledVersion)
    }

    @Test func builtInResourcesAreFound() {
        for name in ModelStore.jsonResources {
            #expect(ModelStore.url(forResource: name, withExtension: "json") != nil, "\(name).json missing")
        }
    }

    @Test func rejectsInvalidSignature() {
        let manifest = Data("{\"version\": 99}".utf8)
        let fakeSignature = Data("bm90IGEgc2lnbmF0dXJl".utf8)   // "not a signature"
        #expect(throws: ModelUpdaterError.self) {
            try ModelUpdater.verifySignature(manifest: manifest, signature: fakeSignature)
        }
    }
}
