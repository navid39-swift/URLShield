//
//  LinkFinderTests.swift
//  URLShield1
//
//  Bare domains without "https://" must be found too (attackers often send them).
//

import Testing
@testable import URLShield1

@MainActor
struct LinkFinderTests {

    let tlds: Set<String> = ["top", "info", "it", "com", "xyz", "zip"]

    @Test func findsBareDomainWithUnusualTLD() {
        #expect(LinkFinder.findLinks(in: "xk7q9z2p.top", knownTLDs: tlds) == ["xk7q9z2p.top"])
    }

    @Test func findsBareDomainWithPathInsideSentence() {
        let links = LinkFinder.findLinks(in: "Conferma qui: poste-it-verifica.info/track, entro oggi.", knownTLDs: tlds)
        #expect(links == ["poste-it-verifica.info/track"])
    }

    @Test func noDuplicateWhenSchemeIsPresent() {
        let links = LinkFinder.findLinks(in: "Apri https://xk7q9z2p.top/login ora", knownTLDs: tlds)
        #expect(links == ["https://xk7q9z2p.top/login"])
    }

    @Test func ignoresEmailsNumbersAndFiles() {
        let text = "Scrivi a mario@poste.it, costo 3.50 euro, versione 1.2, file report.pdf e index.php"
        #expect(LinkFinder.findLinks(in: text, knownTLDs: tlds).isEmpty)
    }

    @Test func ignoresUnknownEndings() {
        #expect(LinkFinder.findLinks(in: "ciao.amico come stai", knownTLDs: tlds).isEmpty)
    }

    @Test func keepsOrderOfLinks() {
        let links = LinkFinder.findLinks(in: "a1b2.xyz poi https://www.poste.it", knownTLDs: tlds)
        #expect(links == ["a1b2.xyz", "https://www.poste.it"])
    }
}
