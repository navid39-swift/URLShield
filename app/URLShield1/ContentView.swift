import SwiftUI

struct ContentView: View {
    @State private var model = ScanViewModel()
    @FocusState private var editorFocused: Bool
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage("hasSeenIntro") private var hasSeenIntro = false
    @State private var activeSheet: ActiveSheet?

    private let settings = LanguageSettings.shared
    private var lang: Bundle { settings.bundle }

    enum ActiveSheet: String, Identifiable {
        case language, about
        var id: String { rawValue }
    }

    private var inputIsEmpty: Bool {
        model.inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {

                    BrandHeader()

                    // Shown when the clipboard probably holds a link
                    if model.clipboardHasLink && model.inputText.isEmpty {
                        HStack(spacing: 12) {
                            Label {
                                Text("You copied a link", bundle: lang)
                            } icon: {
                                Image(systemName: "doc.on.clipboard")
                            }
                            .font(.subheadline.weight(.semibold))
                            Spacer()
                            PasteButton(payloadType: String.self) { strings in
                                model.inputText = strings.joined(separator: "\n")
                                model.scan()
                            }
                        }
                        .padding(12)
                        .background(
                            RoundedRectangle(cornerRadius: 12)
                                .fill(Color.accentColor.opacity(0.12))
                        )
                    }

                    // Input field with placeholder
                    ZStack(alignment: .topLeading) {
                        TextEditor(text: $model.inputText)
                            .focused($editorFocused)
                            .scrollContentBackground(.hidden)
                            .frame(minHeight: 140)
                            .padding(8)
                            .background(
                                RoundedRectangle(cornerRadius: 12)
                                    .fill(Brand.surface)
                            )

                        if model.inputText.isEmpty {
                            Text("e.g. “Your package is on hold: poste-it-verifica.info/track”", bundle: lang)
                                .foregroundStyle(.tertiary)
                                .padding(16)
                                .allowsHitTesting(false)
                        }
                    }

                    HStack {
                        PasteButton(payloadType: String.self) { strings in
                            model.inputText = strings.joined(separator: "\n")
                            model.scan()
                        }
                        Spacer()
                        if !model.inputText.isEmpty {
                            Button(role: .destructive) {
                                model.clear()
                            } label: {
                                Text("Clear", bundle: lang)
                            }
                        }
                    }

                    Button {
                        editorFocused = false
                        model.scan()
                    } label: {
                        Label {
                            Text("Check links", bundle: lang)
                        } icon: {
                            Image(systemName: "shield.lefthalf.filled")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(inputIsEmpty)

                    if let error = model.errorMessage {
                        Text(error).foregroundStyle(.red)
                    }

                    if model.hasScanned && model.results.isEmpty {
                        ContentUnavailableView {
                            Label {
                                Text("No links found", bundle: lang)
                            } icon: {
                                Image(systemName: "link")
                            }
                        } description: {
                            Text("This text doesn't contain any web links.", bundle: lang)
                        }
                    }

                    ForEach(model.results) { analysis in
                        ResultCard(analysis: analysis)
                    }
                }
                .padding()
            }
            .scrollDismissesKeyboard(.interactively)
            .background(Brand.background)
            .navigationTitle("URLShield")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        activeSheet = .about
                    } label: {
                        Label {
                            Text("About", bundle: lang)
                        } icon: {
                            Image(systemName: "info.circle")
                        }
                    }
                }
            }
            .sheet(item: $activeSheet) { sheet in
                switch sheet {
                case .language:
                    LanguagePickerView {
                        let showIntro = !hasSeenIntro
                        hasSeenIntro = true
                        activeSheet = showIntro ? .about : nil
                    }
                case .about:
                    AboutView()
                }
            }
            .onAppear {
                if !settings.hasChosen {
                    activeSheet = .language
                } else if !hasSeenIntro {
                    hasSeenIntro = true
                    activeSheet = .about
                }
                model.refreshClipboardHint()
            }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active {
                    model.refreshClipboardHint()
                }
            }
            .onChange(of: settings.language) { _, _ in
                // Re-run the check so red-flag messages appear in the new language
                if model.hasScanned { model.scan() }
            }
        }
    }
}

#Preview {
    ContentView()
}
