//
//  LinkAnalyzerTests.swift
//  URLShield1
//
//  Created by navid zare on 15/10/2026.
//

import Testing
@testable import URLShield1

@MainActor
struct LinkAnalyzerTests {

    let analyzer: LinkAnalyzer

    init() throws {
        analyzer = try LinkAnalyzer()
    }

    @Test func findsLinkInsideSMS() {
        let results = analyzer.analyze(
            text: "Il tuo pacco è in giacenza. Conferma qui: poste-it-verifica.info/track entro oggi"
        )
        #expect(results.count == 1)
        #expect(results.first?.host == "poste-it-verifica.info")
        #expect(results.first?.level == .likelyPhishing)
        #expect(results.first?.redFlags.contains { $0.message.contains("Poste") } == true)
    }

    @Test func noLinksInNormalMessage() {
        #expect(analyzer.analyze(text: "Ciao, ci vediamo alle 8!").isEmpty)
    }

    @Test func twoLinksInOneMessage() {
        let results = analyzer.analyze(text: "Vai su https://www.poste.it oppure bit.ly/3xYz")
        #expect(results.count == 2)
    }

    @Test func shortenerHidesDestination() throws {
        #expect(try analyzer.analyze(link: "bit.ly/3xYz").level == .hiddenDestination)
    }

    @Test func openPlatformDetected() throws {
        #expect(try analyzer.analyze(link: "https://docs.google.com/forms/d/abc").level == .openPlatform)
    }

    @Test func knownSubdomainIsKnownSite() throws {
        #expect(try analyzer.analyze(link: "https://support.apple.com/en-us/102568").level == .knownSite)
    }

    @Test func ipAddressIsLikelyPhishing() throws {
        #expect(try analyzer.analyze(link: "http://192.168.10.5/login").level == .likelyPhishing)
    }

    @Test func atSymbolTrickIsFlagged() throws {
        let result = try analyzer.analyze(link: "https://paypal.com@evil-login.xyz/verify")
        #expect(result.host == "evil-login.xyz")
        #expect(result.redFlags.contains { $0.message.contains("@") })
    }
}
