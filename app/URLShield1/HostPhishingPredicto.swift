//
//  HostPhishingPredicto.swift
//  URLShield1
//
//  Created by navid zare on 14/10/2026.
//

import CoreML
import Foundation

/// The result for one host.
struct HostPrediction {
    let host: String
    let features: HostFeatures
    /// Probability that the host is phishing, from 0.0 to 1.0.
    let phishingProbability: Double
}

enum HostPredictorError: Error {
    case emptyHost
}

/// Loads the Core ML model once and scores hostnames.
final class HostPhishingPredictor {

    private let model: URLShieldHost
    private let tldRates: TLDRates

    /// By default: the active downloaded update if there is one, else the built-in model.
    /// The updater passes explicit files to self-test a new model before activating it.
    init(modelURL: URL? = ModelStore.activeModelURL, tldRatesURL: URL? = nil) throws {
        let configuration = MLModelConfiguration()
        configuration.computeUnits = .cpuOnly   // tree models run on the CPU anyway

        if let modelURL {
            model = try URLShieldHost(contentsOf: modelURL, configuration: configuration)
        } else {
            model = try URLShieldHost(configuration: configuration)
        }

        if let tldRatesURL {
            tldRates = try JSONDecoder().decode(TLDRates.self, from: Data(contentsOf: tldRatesURL))
        } else {
            tldRates = try TLDRates.loadFromBundle()
        }
    }

    /// Full URL in, prediction out ("https://www.Poste.it/x" → host "poste.it").
    func predict(url: String) throws -> HostPrediction {
        try predict(host: HostFeatureExtractor.extractHost(from: url))
    }

    func predict(host: String) throws -> HostPrediction {
        guard !host.isEmpty else { throw HostPredictorError.emptyHost }

        let f = HostFeatureExtractor.features(for: host, tldRates: tldRates)

        let output = try model.prediction(
            host_length: f.hostLength,
            dot_count: f.dotCount,
            hyphen_count: f.hyphenCount,
            digit_count: f.digitCount,
            digit_ratio: f.digitRatio,
            longest_label_length: f.longestLabelLength,
            char_entropy: f.charEntropy,
            has_ip_address: f.hasIPAddress,
            suspicious_keyword_count: f.suspiciousKeywordCount,
            tld_phish_rate: f.tldPhishRate
        )

        // Label 0 = phishing (same as in Python)
        let phishingProbability = output.probabilities[0] ?? 0

        return HostPrediction(
            host: host,
            features: f,
            phishingProbability: phishingProbability
        )
    }
}
