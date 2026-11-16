//
//  HostPhishingPredictorTests.swift
//  URLShield1
//
//  Created by navid zare on 14/10/2026.
//

import Testing
@testable import URLShield1

@MainActor
struct HostPhishingPredictorTests {

    /// Model v2 values from scikit-learn (urlshield_host_rf_v2.joblib), rounded to 4 decimals.
    let pythonResults: [(url: String, pPhishing: Double)] = [
        ("https://www.google.com", 0.1655),
        ("https://support.apple.com/en-us/102568", 0.9310),
        ("https://www.poste.it", 0.0560),
        ("http://paypal.com.secure-login.xyz/verify", 0.9989),
        ("http://poste-it-verifica.info/track", 0.9022),
        ("https://xk7q9z2p.top", 0.7460),
        ("http://192.168.10.5/login", 1.0000),
    ]

    @Test func coreMLMatchesPython() throws {
        let predictor = try HostPhishingPredictor()

        for expected in pythonResults {
            let result = try predictor.predict(url: expected.url)
            let difference = abs(result.phishingProbability - expected.pPhishing)
            #expect(
                difference < 0.001,
                "\(result.host): swift=\(result.phishingProbability) python=\(expected.pPhishing)"
            )
        }
    }

    @Test func emptyInputThrows() throws {
        let predictor = try HostPhishingPredictor()
        #expect(throws: HostPredictorError.self) {
            try predictor.predict(url: "   ")
        }
    }
}
