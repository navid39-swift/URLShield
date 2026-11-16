//
//  SpotTheFakeView.swift
//  URLShield1
//
//  A short offline game: pick the real website out of two.
//  It teaches the same tricks the analyzer detects.
//  All "fake" domains are invented examples and are never opened.
//

import SwiftUI

// MARK: - Questions

struct FakeQuestion: Identifiable {
    enum Trick {
        case lookalike, extraWords, subdomain, typo, ending

        var tip: String {
            let lang = LanguageSettings.shared.bundle
            switch self {
            case .lookalike:
                return String(localized: "A character imitates another letter, like 1 for l or 0 for o.", bundle: lang)
            case .extraWords:
                return String(localized: "Extra words were added to the real name to make it look official.", bundle: lang)
            case .subdomain:
                return String(localized: "Read the domain from the right: the real website is the part just before the ending.", bundle: lang)
            case .typo:
                return String(localized: "A letter is doubled or missing.", bundle: lang)
            case .ending:
                return String(localized: "The ending was changed to an unusual, cheap one.", bundle: lang)
            }
        }
    }

    let id = UUID()
    let brand: String
    let real: String
    let fake: String
    let trick: Trick
}

enum FakeQuestionBank {
    static let all: [FakeQuestion] = [
        .init(brand: "Poste Italiane", real: "poste.it", fake: "poste-it-verifica.info", trick: .extraWords),
        .init(brand: "PayPal", real: "paypal.com", fake: "paypa1.com", trick: .lookalike),
        .init(brand: "Intesa Sanpaolo", real: "intesasanpaolo.com", fake: "intesasanpaolo.secure-login.com", trick: .subdomain),
        .init(brand: "Amazon", real: "amazon.it", fake: "amaz0n-rimborsi.it", trick: .lookalike),
        .init(brand: "Apple", real: "apple.com", fake: "apple.com-id-verify.top", trick: .subdomain),
        .init(brand: "Netflix", real: "netflix.com", fake: "netfIix-account.com", trick: .lookalike),
        .init(brand: "INPS", real: "inps.it", fake: "inps-rimborso.it-servizi.com", trick: .subdomain),
        .init(brand: "DHL", real: "dhl.it", fake: "dhl-consegna.top", trick: .ending),
        .init(brand: "UniCredit", real: "unicredit.it", fake: "unicreditt.it", trick: .typo),
        .init(brand: "Microsoft", real: "microsoft.com", fake: "rnicrosoft.com", trick: .lookalike),
        .init(brand: "Agenzia delle Entrate", real: "agenziaentrate.gov.it", fake: "agenziaentrate-rimborso.com", trick: .extraWords),
        .init(brand: "WhatsApp", real: "whatsapp.com", fake: "whatsapp-gold.xyz", trick: .ending),
        .init(brand: "Google", real: "google.com", fake: "goog1e.com", trick: .lookalike),
        .init(brand: "Instagram", real: "instagram.com", fake: "instagram.copyright-help.site", trick: .subdomain),
        .init(brand: "Banco BPM", real: "bancobpm.it", fake: "bancobpm.it.verifica-conto.com", trick: .subdomain),
        .init(brand: "iCloud", real: "icloud.com", fake: "icloud-find-my.app", trick: .extraWords),
        .init(brand: "Facebook", real: "facebook.com", fake: "facebok.com", trick: .typo),
        .init(brand: "FinecoBank", real: "finecobank.com", fake: "finecobank.click", trick: .ending),
    ]
}

// MARK: - Game screen

struct SpotTheFakeView: View {
    private enum Phase { case start, playing, finished }

    static let rounds = 10

    @State private var phase: Phase = .start
    @State private var questions: [FakeQuestion] = []
    @State private var index = 0
    @State private var score = 0
    @State private var realFirst = true
    @State private var chosen: String?
    @AppStorage("spotTheFakeBest") private var best = 0

    private var lang: Bundle { LanguageSettings.shared.bundle }

    private var current: FakeQuestion? {
        questions.indices.contains(index) ? questions[index] : nil
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    switch phase {
                    case .start: startView
                    case .playing: roundView
                    case .finished: resultView
                    }
                }
                .padding()
            }
            .background(Brand.background)
            .navigationTitle(Text("Spot the fake", bundle: lang))
        }
    }

    // MARK: Start

    private var startView: some View {
        VStack(alignment: .leading, spacing: 20) {
            Image(systemName: "graduationcap.fill")
                .font(.system(size: 48))
                .foregroundStyle(.tint)
            Text("Which one is the real website?", bundle: lang)
                .font(.title2.bold())
            Text("10 rounds. Tap the official website of the company.", bundle: lang)
                .foregroundStyle(.secondary)
            if best > 0 {
                Text("Best score: \(best)/10", bundle: lang)
                    .font(.headline)
            }
            Button {
                startGame()
            } label: {
                Text("Start", bundle: lang)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
    }

    // MARK: Round

    @ViewBuilder
    private var roundView: some View {
        if let question = current {
            let options = realFirst ? [question.real, question.fake] : [question.fake, question.real]

            Text("Round \(index + 1) of \(Self.rounds)", bundle: lang)
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Text(verbatim: question.brand)
                .font(.title.bold())

            Text("Which one is the real website?", bundle: lang)

            ForEach(options, id: \.self) { domain in
                optionButton(domain, question: question)
            }

            if let chosen {
                let correct = chosen == question.real
                VStack(alignment: .leading, spacing: 8) {
                    Label {
                        Text(correct ? "Correct!" : "Not quite.", bundle: lang)
                    } icon: {
                        Image(systemName: correct ? "checkmark.circle.fill" : "xmark.circle.fill")
                    }
                    .font(.headline)
                    .foregroundStyle(correct ? .green : .red)

                    Text("The real one is \(question.real).", bundle: lang)
                    Text(verbatim: question.trick.tip)
                        .foregroundStyle(.secondary)
                }

                Button {
                    next()
                } label: {
                    Text(index + 1 < Self.rounds ? "Next" : "See result", bundle: lang)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }
        }
    }

    private func optionButton(_ domain: String, question: FakeQuestion) -> some View {
        let isReal = domain == question.real
        let revealed = chosen != nil
        let tint: Color = !revealed ? .accentColor : (isReal ? .green : (chosen == domain ? .red : .secondary))

        return Button {
            guard chosen == nil else { return }
            chosen = domain
            if isReal { score += 1 }
        } label: {
            HStack {
                Text(verbatim: domain)
                    .font(.title3.monospaced().weight(.semibold))
                    .multilineTextAlignment(.leading)
                Spacer()
                if revealed && isReal {
                    Image(systemName: "checkmark.seal.fill")
                } else if revealed && chosen == domain {
                    Image(systemName: "xmark.octagon.fill")
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 14).fill(tint.opacity(0.10)))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(tint.opacity(0.6), lineWidth: 1.5))
        }
        .buttonStyle(.plain)
        .foregroundStyle(revealed ? tint : .primary)
        .disabled(revealed)
    }

    // MARK: Result

    private var resultView: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("You got \(score) out of \(Self.rounds)", bundle: lang)
                .font(.largeTitle.bold())
            Text(resultMessage)
                .font(.title3)
            Text("Best score: \(best)/10", bundle: lang)
                .foregroundStyle(.secondary)
            Button {
                startGame()
            } label: {
                Text("Play again", bundle: lang)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
    }

    private var resultMessage: String {
        switch score {
        case 9...:
            String(localized: "Excellent, scammers will have a hard time with you.", bundle: lang)
        case 6...8:
            String(localized: "Good, but look closely at every character.", bundle: lang)
        default:
            String(localized: "Keep practicing: these tricks fool many people.", bundle: lang)
        }
    }

    // MARK: Game logic

    private func startGame() {
        questions = Array(FakeQuestionBank.all.shuffled().prefix(Self.rounds))
        index = 0
        score = 0
        chosen = nil
        realFirst = Bool.random()
        phase = .playing
    }

    private func next() {
        if index + 1 < Self.rounds {
            index += 1
            chosen = nil
            realFirst = Bool.random()
        } else {
            best = max(best, score)
            phase = .finished
        }
    }
}

#Preview {
    SpotTheFakeView()
}
