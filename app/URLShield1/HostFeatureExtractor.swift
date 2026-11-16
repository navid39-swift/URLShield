//
//  HostFeatureExtractor.swift
//  URLShield1
//
//  Created by navid zare on 14/10/2026.
//

import Foundation

// MARK: - Feature container

/// The 10 model inputs. Names and order match MODEL_COLUMNS in Python.
struct HostFeatures {
    let hostLength: Double
    let dotCount: Double
    let hyphenCount: Double
    let digitCount: Double
    let digitRatio: Double
    let longestLabelLength: Double
    let charEntropy: Double
    let hasIPAddress: Double
    let suspiciousKeywordCount: Double
    let tldPhishRate: Double

    static let names = [
        "host_length", "dot_count", "hyphen_count", "digit_count",
        "digit_ratio", "longest_label_length", "char_entropy",
        "has_ip_address", "suspicious_keyword_count", "tld_phish_rate"
    ]

    var asArray: [Double] {
        [hostLength, dotCount, hyphenCount, digitCount, digitRatio,
         longestLabelLength, charEntropy, hasIPAddress,
         suspiciousKeywordCount, tldPhishRate]
    }
}

// MARK: - TLD rates (tld_rates.json)

struct TLDRates: Decodable {
    let smoothing: Int
    let prior: Double
    let rates: [String: Double]

    /// Unknown TLDs get the prior, exactly like Python's rates.get(tld, prior).
    func rate(for tld: String) -> Double {
        rates[tld] ?? prior
    }

    static func loadFromBundle(_ bundle: Bundle = .main) throws -> TLDRates {
        guard let url = ModelStore.url(forResource: "tld_rates", withExtension: "json", fallback: bundle) else {
            throw CocoaError(.fileNoSuchFile)
        }
        return try JSONDecoder().decode(TLDRates.self, from: Data(contentsOf: url))
    }
}

// MARK: - Extractor (mirrors host_features.py)

enum HostFeatureExtractor {

    static let suspiciousKeywords = [
        "login", "signin", "verify", "verification", "account",
        "password", "secure", "update", "confirm", "bank",
        "support", "wallet"
    ]

    // MARK: extract_host

    static func extractHost(from url: String) -> String {
        var s = url.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        // 1. Remove the scheme (https://, http://, ...)
        if let scheme = s.range(of: #"^[a-z][a-z0-9+.\-]*://"#, options: .regularExpression) {
            s.removeSubrange(scheme)
        }

        // 2. Treat "\" like "/"
        s = s.replacingOccurrences(of: "\\", with: "/")

        // 3. Keep only the part before the first / ? #
        for separator in ["/", "?", "#"] {
            if let r = s.range(of: separator) {
                s = String(s[..<r.lowerBound])
            }
        }

        // 4. Remove "user:password@" (host is after the LAST @)
        if let at = s.range(of: "@", options: .backwards) {
            s = String(s[at.upperBound...])
        }

        // 5. Remove the port, but keep IPv6 literals like [::1]
        if s.hasPrefix("[") {
            if let close = s.range(of: "]") {
                s = String(s[..<close.upperBound])
            } else {
                s += "]"
            }
        } else if let colon = s.range(of: ":") {
            s = String(s[..<colon.lowerBound])
        }

        // 6. Remove trailing dots and a leading "www."
        while s.hasSuffix(".") { s.removeLast() }
        if s.hasPrefix("www.") { s.removeFirst(4) }

        return s
    }

    // MARK: Helpers

    private static func isASCIIDigit(_ c: Unicode.Scalar) -> Bool {
        c.value >= 48 && c.value <= 57    // "0"..."9"
    }

    static func isIPv4(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        for part in parts {
            let scalars = part.unicodeScalars
            guard !scalars.isEmpty, scalars.count <= 3,
                  scalars.allSatisfy({ isASCIIDigit($0) }) else { return false }
            if scalars.count > 1 && scalars.first == "0" { return false }
            guard let value = Int(part), value <= 255 else { return false }
        }
        return true
    }

    static func tldOf(_ host: String) -> String {
        if isIPv4(host) || host.hasPrefix("[") { return "<ip>" }
        if let lastDot = host.range(of: ".", options: .backwards) {
            return String(host[lastDot.upperBound...])
        }
        return host
    }

    static func charEntropy(_ host: String) -> Double {
        let scalars = Array(host.unicodeScalars)
        guard !scalars.isEmpty else { return 0 }
        var counts: [Unicode.Scalar: Int] = [:]
        for c in scalars { counts[c, default: 0] += 1 }
        let n = Double(scalars.count)
        return -counts.values.reduce(0.0) { sum, count in
            let p = Double(count) / n
            return sum + p * log2(p)
        }
    }

    // MARK: The 10 features

    static func features(for host: String, tldRates: TLDRates) -> HostFeatures {
        let scalars = host.unicodeScalars          // Python len() counts code points
        let n = scalars.count
        let digitCount = scalars.filter { isASCIIDigit($0) }.count
        let labels = scalars.split(separator: ".", omittingEmptySubsequences: false)
        let isIP = isIPv4(host) || host.hasPrefix("[")

        return HostFeatures(
            hostLength: Double(n),
            dotCount: Double(scalars.filter { $0 == "." }.count),
            hyphenCount: Double(scalars.filter { $0 == "-" }.count),
            digitCount: Double(digitCount),
            digitRatio: n > 0 ? Double(digitCount) / Double(n) : 0,
            longestLabelLength: Double(labels.map(\.count).max() ?? 0),
            charEntropy: charEntropy(host),
            hasIPAddress: isIP ? 1 : 0,
            suspiciousKeywordCount: Double(suspiciousKeywords.filter { host.contains($0) }.count),
            tldPhishRate: tldRates.rate(for: tldOf(host))
        )
    }
}
