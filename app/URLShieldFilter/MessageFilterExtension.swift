//
//  MessageFilterExtension.swift
//  URLShieldFilter
//
//  iOS calls this for SMS/MMS from unknown senders (once the user enables
//  URLShield in Settings). Everything runs on the device: messages are
//  never sent to a server (no network URL is configured).
//

import IdentityLookup

final class MessageFilterExtension: ILMessageFilterExtension {
    /// Loaded once and reused for every message.
    private static let analyzer = try? LinkAnalyzer()

    /// - Likely phishing link  -> Junk
    /// - Anything else         -> no decision, iOS handles it as usual.
    /// We never promote a message to the main inbox: a link to a known site
    /// (e.g. an open redirect on a big domain) does not prove the sender is honest.
    static func action(for messageBody: String?) -> ILMessageFilterAction {
        guard let body = messageBody, !body.isEmpty, let analyzer else { return .none }
        let results = analyzer.analyze(text: body)

        return results.contains(where: { $0.level == .likelyPhishing }) ? .junk : .none
    }
}

extension MessageFilterExtension: ILMessageFilterQueryHandling, ILMessageFilterCapabilitiesQueryHandling {

    func handle(_ capabilitiesQueryRequest: ILMessageFilterCapabilitiesQueryRequest,
                context: ILMessageFilterExtensionContext,
                completion: @escaping (ILMessageFilterCapabilitiesQueryResponse) -> Void) {
        completion(ILMessageFilterCapabilitiesQueryResponse())
    }

    func handle(_ queryRequest: ILMessageFilterQueryRequest,
                context: ILMessageFilterExtensionContext,
                completion: @escaping (ILMessageFilterQueryResponse) -> Void) {
        let response = ILMessageFilterQueryResponse()
        response.action = Self.action(for: queryRequest.messageBody)
        completion(response)
    }
}
