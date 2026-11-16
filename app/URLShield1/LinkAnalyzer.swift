//
//  LinkAnalyzer.swift
//  URLShield1
//
//  Created by navid zare on 15/10/2026.
//

import Foundation

// MARK: - Result types

enum RiskLevel: String {
    case likelyPhishing      // P >= 0.9, or a strong red flag + P >= 0.5, or an IP address
    case suspicious          // P >= 0.5, or any red flag
    case noRedFlags          // nothing found; never "safe"
    case knownSite           // on the allowlist
    case hiddenDestination   // URL shortener
    case openPlatform        // Google Docs, IPFS, ... anyone can publish
}

struct RedFlag: Hashable {
    let message: String
    let isStrong: Bool
}

struct LinkAnalysis: Identifiable {
    let id = UUID()
    let link: String
    let host: String
    let level: RiskLevel
    let phishingProbability: Double?   // nil when the model was not used
    let redFlags: [RedFlag]
}

// MARK: - Bundled lists

struct SpecialHosts: Decodable {
    let shorteners: [String]
    let platforms: [String]

    static func loadFromBundle(_ bundle: Bundle = .main) throws -> SpecialHosts {
        guard let url = ModelStore.url(forResource: "special_hosts", withExtension: "json", fallback: bundle) else {
            throw CocoaError(.fileNoSuchFile)
        }
        return try JSONDecoder().decode(SpecialHosts.self, from: Data(contentsOf: url))
    }
}

enum Allowlist {
    static func loadFromBundle(_ bundle: Bundle = .main) throws -> Set<String> {
        guard let url = ModelStore.url(forResource: "allowlist", withExtension: "json", fallback: bundle) else {
            throw CocoaError(.fileNoSuchFile)
        }
        return Set(try JSONDecoder().decode([String].self, from: Data(contentsOf: url)))
    }
}

// MARK: - Finding links in text

enum LinkFinder {
    /// Bare domains like "xk7q9z2p.top" or "poste-it.info/track" that
    /// NSDataDetector misses when there is no "https://" and the ending is unusual.
    private static let bareDomainPattern = #"(?<![@\w.\-/])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}|xn--[a-z0-9\-]{1,59}))(?![a-z0-9\-])(?::\d{1,5})?(?:/[^\s]*)?"#
    /// Endings that look like TLDs in noisy data but are file names in a message.
    private static let fileExtensions: Set<String> = [
        "php", "html", "htm", "asp", "aspx", "jsp", "pdf", "jpg", "jpeg", "png",
        "gif", "txt", "doc", "docx", "xls", "xlsx", "exe", "apk",
    ]
    private static let trailingPunctuation = CharacterSet(charactersIn: ".,;:!?)]}\"'»”’")

    /// Every web link in the text, in order, without duplicates.
    /// `knownTLDs`: bare domains count only if their ending is a real TLD
    /// (so "report.pdf" or "v1.2" are not links). Empty = accept any letters.
    static func findLinks(in text: String, knownTLDs: Set<String> = []) -> [String] {
        let range = NSRange(text.startIndex..., in: text)
        var found: [(location: Int, link: String)] = []
        var covered: [NSRange] = []

        // 1. Links with a scheme, or ones Apple recognizes
        if let detector = try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue) {
            for match in detector.matches(in: text, options: [], range: range) {
                guard let scheme = match.url?.scheme?.lowercased(),
                      scheme == "http" || scheme == "https",
                      let textRange = Range(match.range, in: text) else { continue }
                found.append((match.range.location, String(text[textRange])))
                covered.append(match.range)
            }
        }

        // 2. Bare domains Apple missed
        guard let bareDomain = try? NSRegularExpression(pattern: bareDomainPattern, options: [.caseInsensitive]) else {
            return found.map(\.link)
        }
        for match in bareDomain.matches(in: text, options: [], range: range) {
            if covered.contains(where: { NSIntersectionRange($0, match.range).length > 0 }) { continue }
            guard let textRange = Range(match.range, in: text),
                  let tldRange = Range(match.range(at: 2), in: text) else { continue }
            let tld = text[tldRange].lowercased()
            if fileExtensions.contains(tld) { continue }
            if !knownTLDs.isEmpty && !knownTLDs.contains(tld) { continue }
            var link = String(text[textRange])
            while let last = link.unicodeScalars.last, trailingPunctuation.contains(last) {
                link.removeLast()
            }
            found.append((match.range.location, link))
        }

        var links: [String] = []
        for item in found.sorted(by: { $0.location < $1.location }) where !links.contains(item.link) {
            links.append(item.link)
        }
        return links
    }
}

// MARK: - The analyzer

final class LinkAnalyzer {

    static let likelyPhishingThreshold = 0.9
    static let suspiciousThreshold = 0.5

    /// Brand word -> its official domains.
    static let brands: [String: [String]] = [
        "paypal": ["paypal.com", "paypal.it"],
        "apple": ["apple.com", "icloud.com"],
        "icloud": ["icloud.com", "apple.com"],
        "amazon": ["amazon.it", "amazon.com"],
        "poste": ["poste.it", "posteitaliane.it"],
        "intesa": ["intesasanpaolo.com"],
        "unicredit": ["unicredit.it"],
        "netflix": ["netflix.com"],
        "microsoft": ["microsoft.com"],
        "dhl": ["dhl.com", "dhl.it"],
        "inps": ["inps.it"],
    ]

    private let predictor: HostPhishingPredictor
    private let special: SpecialHosts
    private let allowlist: Set<String>
    private let knownTLDs: Set<String>

    init() throws {
        predictor = try HostPhishingPredictor()
        special = try SpecialHosts.loadFromBundle()
        allowlist = try Allowlist.loadFromBundle()
        knownTLDs = Set((try? TLDRates.loadFromBundle())?.rates.keys.map { $0 } ?? [])
    }

    /// Analyze a whole SMS: find the links, then judge each one.
    func analyze(text: String) -> [LinkAnalysis] {
        LinkFinder.findLinks(in: text, knownTLDs: knownTLDs).compactMap { try? analyze(link: $0) }
    }

    /// Analyze one link.
    func analyze(link: String) throws -> LinkAnalysis {
        let host = HostFeatureExtractor.extractHost(from: link)
        guard !host.isEmpty else { throw HostPredictorError.emptyHost }

        // 1. Shortener: the real destination is hidden
        if special.shorteners.contains(host) {
            return LinkAnalysis(link: link, host: host, level: .hiddenDestination,
                                phishingProbability: nil, redFlags: [
                RedFlag(message: String(localized: "Shortened link: the real destination is hidden.", bundle: LanguageSettings.shared.bundle), isStrong: false)
            ])
        }

        // 2. Open platform: the domain says nothing about this page
        let isIPFS = host.split(separator: ".").contains { $0.contains("ipfs") }
        if special.platforms.contains(host) || isIPFS {
            return LinkAnalysis(link: link, host: host, level: .openPlatform,
                                phishingProbability: nil, redFlags: [
                RedFlag(message: String(localized: "Hosted on a platform where anyone can publish content.", bundle: LanguageSettings.shared.bundle), isStrong: false)
            ])
        }

        // 3. Known domain
        if isAllowlisted(host) {
            return LinkAnalysis(link: link, host: host, level: .knownSite,
                                phishingProbability: nil, redFlags: [])
        }

        // 4. Red-flag rules
        var flags: [RedFlag] = []
        let isIP = HostFeatureExtractor.isIPv4(host) || host.hasPrefix("[")

        if isIP {
            flags.append(RedFlag(message: String(localized: "Uses a raw IP address instead of a website name.", bundle: LanguageSettings.shared.bundle), isStrong: true))
        }
        if Self.hasUserInfo(link) {
            flags.append(RedFlag(message: String(localized: "Contains an @ before the address, a trick to hide the real site.", bundle: LanguageSettings.shared.bundle), isStrong: true))
        }
        if host.contains("xn--") {
            flags.append(RedFlag(message: String(localized: "Uses special characters that can imitate normal letters.", bundle: LanguageSettings.shared.bundle), isStrong: false))
        }
        let tokens = host.split { $0 == "." || $0 == "-" }
        for brand in Self.brands.keys.sorted() {
            let official = Self.brands[brand] ?? []
            let mentionsBrand = tokens.contains { $0.hasPrefix(brand) }
            let isOfficial = official.contains { Self.isUnder(host, $0) }
            if mentionsBrand && !isOfficial {
                flags.append(RedFlag(message: String(localized: "Mentions \u{201C}\(brand.capitalized)\u{201D} but is not its official website.", bundle: LanguageSettings.shared.bundle), isStrong: true))
            }
        }

        let imitated = TyposquatDetector.imitatedBrand(host: host)
        if let imitated {
            flags.append(RedFlag(message: String(localized: "Looks very similar to \u{201C}\(imitated)\u{201D}, a common trick called typosquatting.", bundle: LanguageSettings.shared.bundle), isStrong: true))
        }

        // 5. Core ML
        let p = try predictor.predict(host: host).phishingProbability
        let hasStrongFlag = flags.contains { $0.isStrong }

        let level: RiskLevel
        if p >= Self.likelyPhishingThreshold || (hasStrongFlag && p >= Self.suspiciousThreshold) || isIP || imitated != nil {
            level = .likelyPhishing
        } else if p >= Self.suspiciousThreshold || !flags.isEmpty {
            level = .suspicious
        } else {
            level = .noRedFlags
        }

        return LinkAnalysis(link: link, host: host, level: level,
                            phishingProbability: p, redFlags: flags)
    }

    // MARK: Helpers

    /// host is the domain itself or one of its subdomains.
    static func isUnder(_ host: String, _ domain: String) -> Bool {
        host == domain || host.hasSuffix("." + domain)
    }

    /// Checks support.apple.com, then apple.com, against the allowlist.
    private func isAllowlisted(_ host: String) -> Bool {
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return false }
        for i in 0...(labels.count - 2) {
            if allowlist.contains(labels[i...].joined(separator: ".")) { return true }
        }
        return false
    }

    /// True for tricks like https://paypal.com@evil.com
    private static func hasUserInfo(_ link: String) -> Bool {
        var s = link.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let scheme = s.range(of: #"^[a-z][a-z0-9+.\-]*://"#, options: .regularExpression) {
            s.removeSubrange(scheme)
        }
        s = s.replacingOccurrences(of: "\\", with: "/")
        for separator in ["/", "?", "#"] {
            if let r = s.range(of: separator) { s = String(s[..<r.lowerBound]) }
        }
        return s.contains("@")
    }
}
