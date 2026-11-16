//
//  TyposquatDetector.swift
//  URLShield1
//
//  Detects domains that imitate a known brand with small changes:
//  paypa1.com, amaz0n.it, rnicrosoft.com, netfllx-login.com ...
//

import Foundation

enum TyposquatDetector {

    /// Brand name as it appears in the official domain -> name shown to the user.
    static let protectedNames: [String: String] = [
        "agenziaentrate": "Agenzia delle Entrate",
        "amazon": "Amazon",
        "apple": "Apple",
        "bancobpm": "Banco BPM",
        "bper": "BPER",
        "dhl": "DHL",
        "facebook": "Facebook",
        "finecobank": "FinecoBank",
        "google": "Google",
        "icloud": "iCloud",
        "inps": "INPS",
        "instagram": "Instagram",
        "intesasanpaolo": "Intesa Sanpaolo",
        "microsoft": "Microsoft",
        "netflix": "Netflix",
        "paypal": "PayPal",
        "poste": "Poste",
        "posteitaliane": "Poste Italiane",
        "unicredit": "UniCredit",
        "whatsapp": "WhatsApp",
    ]

    private static let sortedNames = protectedNames.keys.sorted()

    /// The brand this host imitates, or nil.
    /// Exact brand names are not reported here: the allowlist and the
    /// brand rule in LinkAnalyzer already handle those.
    static func imitatedBrand(host: String) -> String? {
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return nil }

        // "secure-paypa1.com" -> check "secure-paypa1", "secure", "paypa1"
        let core = labels[labels.count - 2]
        var candidates = [core]
        candidates += core.split(separator: "-").map(String.init)

        for candidate in candidates where !candidate.isEmpty {
            for name in sortedNames where candidate != name {
                // 1. Look-alike characters: paypa1 -> paypal, rnicrosoft -> microsoft
                if lookalikeVariants(of: candidate).contains(name) {
                    return protectedNames[name]
                }
                // 2. One or two typing changes, only for longer names
                //    (short names like "apple" would match normal words such as "applet")
                let limit = name.count >= 10 ? 2 : (name.count >= 6 ? 1 : 0)
                if limit > 0,
                   abs(candidate.count - name.count) <= limit,
                   levenshtein(candidate, name) <= limit {
                    return protectedNames[name]
                }
                // 3. Brand with digits mixed in: appl22, apple2024, dhl24, g00gle1
                //    Remove the digits, then compare (one change allowed for names of 5+ letters).
                if candidate.contains(where: { $0.isNumber }) {
                    let letters = String(candidate.filter { !$0.isNumber })
                    if letters == name ||
                       (name.count >= 5 && letters.count >= name.count - 1 &&
                        levenshtein(letters, name) <= 1) {
                        return protectedNames[name]
                    }
                }
            }
        }
        return nil
    }

    /// Replaces characters that are often used to imitate letters.
    static func lookalikeVariants(of text: String) -> Set<String> {
        var base = text
            .replacingOccurrences(of: "rn", with: "m")
            .replacingOccurrences(of: "vv", with: "w")
        for (fake, real) in [("0", "o"), ("3", "e"), ("4", "a"), ("5", "s"), ("7", "t")] {
            base = base.replacingOccurrences(of: fake, with: real)
        }
        // "1" can imitate both "l" and "i"
        return [
            base.replacingOccurrences(of: "1", with: "l"),
            base.replacingOccurrences(of: "1", with: "i"),
        ]
    }

    /// Number of single-character edits needed to turn a into b.
    static func levenshtein(_ a: String, _ b: String) -> Int {
        let a = Array(a), b = Array(b)
        if a.isEmpty { return b.count }
        if b.isEmpty { return a.count }
        var previous = Array(0...b.count)
        for i in 1...a.count {
            var current = [i] + Array(repeating: 0, count: b.count)
            for j in 1...b.count {
                let cost = a[i - 1] == b[j - 1] ? 0 : 1
                current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            }
            previous = current
        }
        return previous[b.count]
    }
}
