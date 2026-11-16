//
//  TyposquatDetectorTests.swift
//  URLShield1Tests
//

import Testing
@testable import URLShield1

@MainActor
struct TyposquatDetectorTests {

    @Test(arguments: [
        ("paypa1.com", "PayPal"),             // 1 instead of l
        ("amaz0n.it", "Amazon"),              // 0 instead of o
        ("rnicrosoft.com", "Microsoft"),      // rn instead of m
        ("faceb00k.com", "Facebook"),
        ("intesasanpaoio.com", "Intesa Sanpaolo"),   // one letter changed
        ("secure-netfllx-login.com", "Netflix"),     // inside a longer name
        ("whatsap.com", "WhatsApp"),          // one letter missing
        ("appl22.com", "Apple"),              // letter dropped, digits added
        ("apple2024-login.com", "Apple"),     // brand + digits
        ("dhl24.it", "DHL"),                  // short brand + digits
    ])
    func detectsImitations(host: String, brand: String) {
        #expect(TyposquatDetector.imitatedBrand(host: host) == brand)
    }

    @Test(arguments: [
        "poste.it", "google.com", "applet.com", "amazing.com",
        "wikipedia.org", "github.com", "corriere.it", "unina.it", "example.com",
        "app4u.com", "web3.com", "covid19.org", "24ore.it",
    ])
    func ignoresNormalDomains(host: String) {
        #expect(TyposquatDetector.imitatedBrand(host: host) == nil)
    }

    @Test func levenshteinBasics() {
        #expect(TyposquatDetector.levenshtein("paypal", "paypal") == 0)
        #expect(TyposquatDetector.levenshtein("paypal", "paypai") == 1)
        #expect(TyposquatDetector.levenshtein("", "abc") == 3)
    }

    @Test func analyzerFlagsTyposquatting() throws {
        let analyzer = try LinkAnalyzer()
        let result = try analyzer.analyze(link: "http://paypa1.com/login")
        #expect(result.redFlags.contains { $0.message.contains("PayPal") })
        #expect(result.level == .likelyPhishing || result.level == .suspicious)
    }
}
