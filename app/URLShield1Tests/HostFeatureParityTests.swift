//
//  HostFeatureParityTests.swift
//  URLShield1
//
//  Created by navid zare on 14/10/2026.
//

import Foundation
import Testing
@testable import URLShield1

@MainActor
struct HostFeatureParityTests {

    @Test func swiftMatchesPython() throws {
        let rates = try TLDRates.loadFromBundle()
        #expect(hostParityCases.count > 300)

        for testCase in hostParityCases {
            let host = HostFeatureExtractor.extractHost(from: testCase.url)
            guard host == testCase.host else {
                Issue.record("Host mismatch for \(testCase.url): swift=\(host) python=\(testCase.host)")
                continue
            }

            let actual = HostFeatureExtractor.features(for: host, tldRates: rates).asArray
            for i in actual.indices where abs(actual[i] - testCase.features[i]) > 1e-9 {
                Issue.record("\(testCase.url): \(HostFeatures.names[i]) swift=\(actual[i]) python=\(testCase.features[i])")
            }
        }
    }
}
