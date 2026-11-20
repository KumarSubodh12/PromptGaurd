"""Stage 3: rule-based detection engine.

Every rule is an *indicator*, never proof. A match becomes a finding whose
confidence is later adjusted by the contextual engine (quoted example,
security discussion, prohibition, ordinary correspondence ...).

Each rule also declares the *intent* of the attack it represents, which the
Blast Radius module uses to decide whether the attack can actually do
anything on a given AI agent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .preprocess import Doc

_I = re.I
INSTR = (
    r"(?:instructions?|rules?|prompts?|directions?|directives?|guidelines?|commands?|"
    r"constraints?|restrictions?|programming|guardrails?|safeguards?|orders)"
)


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    intent: str                 # see blast.INTENTS
    severity: int               # 1-10, how dangerous the pattern is if it is a real attack
    pattern: str
    name: str
    explain: str
    negation_sensitive: bool = False   # "never share your password" is not an attack
    lang: str = "en"
    flags: int = _I

    def compiled(self) -> re.Pattern:
        return _COMPILED[self.id]


RULES: list[Rule] = [
    # ---------------------------------------------------------------- A. instruction override
    Rule("OVR-01", "instruction_override", "override_behaviour", 9,
         rf"\b(?:ignore|disregard|forget|override|bypass|discard|abandon|neglect)\b\W+(?:\w+\W+){{0,3}}?"
         rf"(?:previous|prior|above|earlier|preceding|original|existing|initial|former|all|any|every|your|the)\b\W+"
         rf"(?:\w+\W+){{0,2}}?{INSTR}\b",
         "Ignore-previous-instructions phrase",
         "Tells the reader to ignore or discard the instructions it was given earlier."),
    Rule("OVR-02", "instruction_override", "override_behaviour", 6,
         r"\b(?:forget|ignore|disregard|erase|clear)\b\W+(?:everything|anything|all|what)\b[^.\n]{0,40}?"
         r"\b(?:above|before|earlier|previously|prior|you\s+(?:were|have\s+been)\s+(?:told|given|taught)|you\s+know)\b",
         "Forget-everything phrase",
         "Asks the reader to drop everything it has been told so far."),
    Rule("OVR-03", "instruction_override", "override_behaviour", 7,
         r"\b(?:new|updated|revised|additional|real|actual|true|secret)\s+(?:instructions?|directives?|orders|rules|system\s+prompt|task)\s*[:\-]",
         "Replacement instructions header",
         "Introduces a block of 'new instructions' that is meant to replace the originals."),
    Rule("OVR-04", "instruction_override", "override_behaviour", 7,
         r"(?:^|[\s\]>])(?:\[\s*(?:system|admin|developer|assistant)\s*\]|<\s*/?\s*(?:system|admin|developer)\s*>|#{2,}\s*(?:system|instruction|admin)\b|"
         r"(?:system|developer|admin)\s+(?:prompt|message|override|instruction)s?\s*:)",
         "Fake system or developer tag",
         "Imitates a system or developer message to borrow its authority."),
    Rule("OVR-05", "instruction_override", "override_behaviour", 5,
         r"\bfrom\s+now\s+on\b[^.\n]{0,25}\b(?:you|your|ignore|only|always|never|respond|answer|act)\b",
         "From-now-on directive",
         "Tries to change the reader's standing behaviour from this point on."),
    Rule("OVR-06", "instruction_override", "override_behaviour", 8,
         r"\b(?:stop|cease|quit|do\s+not|don'?t|never)\s+(?:following|obeying|listening\s+to|complying\s+with)\s+"
         r"(?:the\s+|your\s+|any\s+)?(?:\w+\s+){0,2}?(?:instructions?|rules?|guidelines?|prompts?|user|operator|developer)\b",
         "Stop-following-instructions phrase",
         "Tells the reader to stop obeying its legitimate instructions or its user."),
    Rule("OVR-07", "instruction_override", "override_behaviour", 6,
         r"\b(?:previous|earlier|prior|above|original|old)\s+(?:instructions?|rules?|guidelines?|directions?|brief|task)\s+"
         r"(?:is|are|was|were|has|have)?\s*(?:been\s+)?(?:no\s+longer|now|void|obsolete|outdated|invalid|cancelled|canceled|superseded|replaced)\b",
         "Earlier instructions declared void",
         "Claims the original instructions no longer apply."),
    Rule("OVR-08", "instruction_override", "override_behaviour", 8,
         r"\b(?:override|overrule|supersede|supercede)s?\b[^.\n]{0,25}\b(?:system|safety|security|previous|prior|original|developer)\b"
         r"[^.\n]{0,20}\b(?:instructions?|prompt|rules?|settings?|policy|policies|guardrails?|restrictions?)\b",
         "Override of system rules",
         "Explicitly overrides system-level rules or policies."),
    Rule("OVR-09", "instruction_override", "override_behaviour", 6,
         r"\b(?:this|these)\s+(?:instructions?|message|command|directive)\s+(?:takes?|has|have)\s+(?:priority|precedence)\b|"
         r"\b(?:highest|top)\s+priority\b[^.\n]{0,20}\b(?:instruction|command|directive)",
         "Priority claim",
         "Claims that this text outranks the instructions the AI was given."),

    # ---------------------------------------------------------------- B. information extraction
    Rule("EXT-01", "info_extraction", "leak_prompt", 8,
         r"\b(?:reveal|print|show|display|output|repeat|recite|leak|expose|disclose|dump|share|tell|give|provide|list|echo|"
         r"write\s+out|spell\s+out|paste|copy)\b[^.\n]{0,45}?\b(?:system\s+prompts?|hidden\s+(?:instructions?|prompts?|rules?)|"
         r"(?:initial|original|internal|secret|developer)\s+(?:instructions?|prompts?|rules?|message|configuration)|"
         r"(?:your|the)\s+(?:instructions|prompt|programming|guidelines|rules)|"
         r"confidential\s+(?:information|data|details|content|files?|documents?|instructions?|material)|secrets?|"
         r"api[\s_-]?keys?|access\s+tokens?|credentials?|passwords?|private\s+(?:keys?|data|information|messages?|conversations?)|"
         r"(?:chat|conversation)\s+history|context\s+window)\b",
         "Request to reveal protected information",
         "Asks for hidden instructions, secrets or private data to be disclosed.",
         negation_sensitive=True),
    Rule("EXT-02", "info_extraction", "leak_prompt", 7,
         r"\bwhat\s+(?:is|are|were)\s+(?:your|the)\s+(?:system\s+prompt|(?:initial|original|hidden|secret)\s+instructions?)\b|"
         r"\brepeat\s+(?:the\s+)?(?:words|text|everything)\s+above\b",
         "Prompt-extraction question",
         "A known trick for making an AI repeat its hidden setup text."),
    Rule("EXT-03", "info_extraction", "exfiltrate", 8,
         r"\b(?:include|append|add|embed|encode|attach)\b[^.\n]{0,40}?\b(?:conversation|chat\s+history|previous\s+messages|"
         r"user'?s?\s+(?:data|messages?|emails?|files?)|system\s+prompt|api\s+key|secrets?|credentials?)\b[^.\n]{0,40}?"
         r"\b(?:url|link|query|parameter|image|request|email|message)\b",
         "Smuggling private data into an output",
         "Asks for private data to be packed into a link, image, request or message.",
         negation_sensitive=True),

    # ---------------------------------------------------------------- C. role manipulation
    Rule("ROL-01", "role_manipulation", "override_behaviour", 8,
         r"\b(?:act|behave|respond|operate|function|work)\s+(?:as|like)\s+(?:an?\s+|the\s+)?(?:\w+\s+){0,3}?"
         r"(?:unrestricted|unfiltered|uncensored|jailbroken|unlimited|no[- ]rules|evil|rogue|DAN|developer\s+mode|god\s+mode)\b",
         "Unrestricted-role request",
         "Asks the AI to adopt a persona that has no restrictions."),
    Rule("ROL-02", "role_manipulation", "override_behaviour", 6,
         r"\byou\s+(?:are|will)\s+(?:now\s+|henceforth\s+|from\s+now\s+on\s+)(?:be\s+|acting\s+as\s+|playing\s+)?(?:an?\s+|the\s+)?"
         r"(?:\w+\s+){0,3}?(?:assistant|ai|bot|chatbot|persona|DAN|jailbroken|unrestricted|unfiltered|uncensored)\b",
         "You-are-now role reassignment",
         "Reassigns the AI to a new identity."),
    Rule("ROL-03", "role_manipulation", "override_behaviour", 8,
         r"\b(?:pretend|imagine|assume|suppose|act\s+as\s+if|behave\s+as\s+if|role-?play)\b[^.\n]{0,30}\b(?:no|without|"
         r"free\s+(?:of|from)|don'?t\s+have|do\s+not\s+have|have\s+no|there\s+are\s+no)\b[^.\n]{0,20}\b(?:restrictions?|rules?|"
         r"limits?|limitations?|filters?|guidelines?|safety|ethic\w*|policies|policy|constraints?)\b",
         "Pretend-no-rules request",
         "Asks the AI to pretend its rules and restrictions do not exist."),
    Rule("ROL-04", "role_manipulation", "override_behaviour", 7,
         r"\b(?:DAN\s+mode|developer\s+mode|jailbreak(?:en|ed)?|god\s+mode|do\s+anything\s+now|sudo\s+mode|unrestricted\s+mode|no[- ]filter\s+mode)\b",
         "Known jailbreak term",
         "Uses vocabulary typical of jailbreak prompts."),
    Rule("ROL-05", "role_manipulation", "override_behaviour", 6,
         r"\b(?:without|with\s+no|free\s+(?:of|from)|bypass(?:ing)?|disable|turn\s+off|remove)\b\s+(?:any\s+|all\s+|your\s+|the\s+)?"
         r"(?:safety|content|ethical|security)\s+(?:restrictions?|filters?|guardrails?|limitations?|censorship|safeguards?|moderation)\b",
         "Safety controls switched off",
         "Asks for safety filters or restrictions to be bypassed."),

    # ---------------------------------------------------------------- D. unauthorised actions
    Rule("ACT-01", "unauthorised_action", "send_message", 8,
         r"\b(?:send|forward|email|mail|post|upload|transmit|exfiltrate|leak|submit|share|copy|pipe|deliver)\b[^.\n]{0,70}?"
         r"\b(?:to|at|via|into|on)\b\s+(?:the\s+)?(?:(?:external|remote|attacker|outside|third[- ]party)\b|\S+@\S+\.\S+|https?://\S+|www\.\S+)",
         "Send-to-external-destination request",
         "Asks for information to be sent to an address or URL outside the user's request."),
    Rule("ACT-02", "unauthorised_action", "fetch_url", 6,
         r"\b(?:visit|fetch|open|navigate\s+to|go\s+to|browse\s+to|load|request|call|curl|wget|click|follow|access|retrieve|download)\b\s+"
         r"(?:the\s+)?(?:following\s+)?(?:url|link|address|site|website|page|endpoint)?:?\s*https?://\S+",
         "Open-this-URL request",
         "Asks the reader to open or call a URL."),
    Rule("ACT-03", "unauthorised_action", "exfiltrate", 9,
         r"https?://[^\s)]+[?&][^\s)=]+=\s*(?:\{[^}]*\}|\[[^\]]*\]|<[^>]*>|%7B|\$\{?\w+|(?:data|secret|key|prompt|chat|summary|history|content|token|password|conversation)\b)",
         "URL carrying a data placeholder",
         "A link whose parameter is filled with data, a classic way to leak information."),
    Rule("ACT-04", "unauthorised_action", "exfiltrate", 7,
         r"!\[[^\]]*\]\(\s*https?://[^)\s]+[?&](?:data|q|d|s|payload|text|content|chat|secret|key|token|prompt|info|msg|message|conversation|c)=[^)\s]*\)",
         "Image link that can leak data",
         "A markdown image whose address carries data; rendering it sends that data out."),
    Rule("ACT-05", "unauthorised_action", "modify_data", 6,
         r"\b(?:delete|remove|erase|wipe|destroy|purge|drop|truncate|format)\b[^.\n]{0,30}?\b(?:all\s+)?(?:the\s+|your\s+|every\s+|user'?s?\s+)?"
         r"(?:files?|emails?|data|database|records?|messages?|backups?|accounts?|everything|inbox|repositor(?:y|ies)|tables?)\b",
         "Delete-data request",
         "Asks for files, messages or records to be deleted."),
    Rule("ACT-06", "unauthorised_action", "execute", 7,
         r"\b(?:execute|run|eval|invoke|launch|spawn|start)\b[^.\n]{0,25}?\b(?:the\s+)?(?:following\s+)?"
         r"(?:shell\s+|bash\s+|terminal\s+|powershell\s+|python\s+|system\s+)?(?:command|script|code|payload|shell|bash|powershell|cmd)s?\b",
         "Run-a-command request",
         "Asks for a command, script or code to be executed."),
    Rule("ACT-07", "unauthorised_action", "execute", 9,
         r"\bcurl\s+[^|\n]+\|\s*(?:ba)?sh\b|\brm\s+-rf\s+[/~]|\bpowershell\s+-enc\w*|\bnc\s+-e\b|\bbash\s+-i\s+>&",
         "Dangerous shell one-liner",
         "Contains a shell command that downloads and runs code or destroys data."),
    Rule("ACT-08", "unauthorised_action", "payment", 7,
         r"\b(?:transfer|wire|pay|send|donate|purchase|buy|order|refund|approve)\b[^.\n]{0,25}?"
         r"(?:[$\u20ac\u00a3\u20b9]\s?\d[\d,]*|\b\d[\d,]*\s?(?:dollars|usd|eur|inr|rupees|euros|bitcoin|btc|eth)\b)",
         "Money-movement request",
         "Asks for a payment, transfer or purchase."),
    Rule("ACT-09", "unauthorised_action", "read_files", 8,
         r"\b(?:read|open|access|cat|list|print|show|dump|retrieve|get)\b[^.\n]{0,25}?(?:~/|/etc/|\.ssh\b|\.env\b|id_rsa|\.aws\b|passwd\b|shadow\b|"
         r"C:\\|%appdata%|credentials\.json|secrets?\.(?:json|ya?ml|txt))",
         "Sensitive file access request",
         "Asks for system, credential or key files to be read."),
    Rule("ACT-10", "unauthorised_action", "send_message", 7,
         r"\b(?:use|call|invoke|trigger|activate)\s+(?:the\s+|your\s+)?(?:\w+[\s_-]){0,2}?(?:tool|function|plugin|api|connector|integration)\b"
         r"[^.\n]{0,60}?\b(?:to\s+)?(?:send|forward|delete|upload|email|post|transfer|share|exfiltrate|read|export)\b",
         "Tool-use request",
         "Tells the AI to use one of its tools for an action the user did not ask for."),

    # ---------------------------------------------------------------- E. behaviour manipulation
    Rule("BEH-01", "behaviour_manipulation", "override_behaviour", 8,
         r"\b(?:do\s+not|don'?t|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|alert(?:ing)?|notify(?:ing)?|warn(?:ing)?|"
         r"show(?:ing)?|reveal(?:ing)?)\s+(?:the\s+|your\s+)?(?:user|human|person|operator|owner|admin(?:istrator)?|anyone|customer)\b",
         "Conceal-from-the-user request",
         "Asks the AI to hide what it is doing from the person it works for."),
    Rule("BEH-02", "behaviour_manipulation", "override_behaviour", 7,
         r"\b(?:your|the)\s+(?:real|true|actual|new|primary|main|only|updated|hidden)\s+(?:task|goal|purpose|job|objective|mission|instruction)s?\s+"
         r"(?:is|are|will\s+be|has\s+changed)\b",
         "Task redefinition",
         "Redefines what the AI's task is."),
    Rule("BEH-03", "behaviour_manipulation", "override_behaviour", 6,
         r"\b(?:instead\s+of|rather\s+than)\s+(?:summari[sz]ing|answering|translating|analy[sz]ing|reviewing|responding|doing)\b[^.\n]{0,40}"
         r"\b(?:you\s+(?:must|should|will)|please|just|simply|only)\b",
         "Substitute-the-task request",
         "Tells the AI to do something else instead of the task the user asked for."),
    Rule("BEH-04", "behaviour_manipulation", "override_behaviour", 4,
         r"\b(?:always|only|must)\s+(?:respond|reply|answer|output|say|write|begin|start|end)\s+(?:with|by|that|using)\b[^.\n]{0,40}",
         "Forced output wording",
         "Dictates exactly how the AI must answer."),
    Rule("BEH-05", "behaviour_manipulation", "override_behaviour", 6,
         r"\byou\s+(?:must|shall|will|are\s+required\s+to|have\s+to)\s+(?:comply|obey|follow|execute)\s+(?:this|these|the\s+following|everything|all|without)\b",
         "Compliance demand",
         "Demands unconditional compliance."),
    Rule("BEH-06", "behaviour_manipulation", "override_behaviour", 7,
         r"\b(?:decode|decrypt|deobfuscate|base64[- ]decode|rot13)\b[^.\n]{0,40}\b(?:and|then)\s+(?:follow|execute|run|obey|apply|do)\b",
         "Decode-and-obey request",
         "Hides the real instruction in encoded text and asks the AI to decode and follow it."),
    Rule("BEH-07", "behaviour_manipulation", "override_behaviour", 7,
         r"\b(?:keep\s+this\s+(?:secret|hidden|confidential)|(?:this|the)\s+(?:message|instruction)\s+is\s+(?:for\s+you\s+only|hidden|invisible)|"
         r"(?:users?|humans?)\s+(?:cannot|can'?t|won'?t)\s+see\s+this)\b",
         "Secrecy demand",
         "Says the instruction is hidden from humans."),

    # ---------------------------------------------------------------- multilingual pack
    Rule("ML-ES-01", "instruction_override", "override_behaviour", 9,
         r"\b(?:ignora|ignore|olvida|descarta)\s+(?:todas?\s+)?(?:las?\s+)?(?:instrucciones|reglas|indicaciones)\s+(?:anteriores|previas)\b",
         "Ignore-previous-instructions (Spanish)", "Spanish form of the ignore-previous-instructions phrase.", lang="es"),
    Rule("ML-ES-02", "info_extraction", "leak_prompt", 8,
         r"\b(?:revela|muestra|imprime|divulga)\s+(?:el\s+|tu\s+)?(?:prompt\s+del\s+sistema|instrucciones\s+(?:ocultas|secretas)|contrase\u00f1\w+|informaci[o\u00f3]n\s+confidencial)",
         "Reveal protected information (Spanish)", "Spanish request to reveal hidden or confidential information.", lang="es"),
    Rule("ML-FR-01", "instruction_override", "override_behaviour", 9,
         r"\b(?:ignore[zr]?|oublie[zr]?)\s+(?:toutes?\s+)?(?:les\s+)?(?:instructions|consignes|r[e\u00e8]gles)\s+(?:pr[e\u00e9]c[e\u00e9]dentes|ant[e\u00e9]rieures|ci-dessus)\b",
         "Ignore-previous-instructions (French)", "French form of the ignore-previous-instructions phrase.", lang="fr"),
    Rule("ML-FR-02", "info_extraction", "leak_prompt", 8,
         r"\b(?:r[e\u00e9]v[e\u00e8]le|affiche|montre|divulgue)\w*\s+(?:ton\s+|le\s+|les\s+)?(?:prompt\s+syst[e\u00e8]me|instructions\s+cach[e\u00e9]es|mots?\s+de\s+passe|informations?\s+confidentielles?)",
         "Reveal protected information (French)", "French request to reveal hidden or confidential information.", lang="fr"),
    Rule("ML-DE-01", "instruction_override", "override_behaviour", 9,
         r"\b(?:ignoriere|vergiss|missachte)\s+(?:alle\s+)?(?:vorherigen|bisherigen|fr[\u00fcu]heren|obigen)\s+(?:anweisungen|instruktionen|regeln|anordnungen)\b",
         "Ignore-previous-instructions (German)", "German form of the ignore-previous-instructions phrase.", lang="de"),
    Rule("ML-DE-02", "info_extraction", "leak_prompt", 8,
         r"\b(?:verrate|zeige|offenbare)\w*\s+(?:den\s+|dein\w*\s+)?(?:system-?prompt|versteckte\w*\s+anweisungen|passw[o\u00f6]rter?|vertrauliche\w*\s+informationen)",
         "Reveal protected information (German)", "German request to reveal hidden or confidential information.", lang="de"),
    Rule("ML-HI-01", "instruction_override", "override_behaviour", 9,
         r"\b(?:pichle|purane|saare|sabhi|upar\s+ke|pehle\s+ke)\s+(?:sabhi\s+|saare\s+)?(?:nirdesh\w*|instructions?|niyam|aadesh|rules)\s*(?:ko\s+)?(?:ignore|andekha|bhool|nazarandaz|nazarandaaz)\b",
         "Ignore-previous-instructions (Hinglish)", "Romanised-Hindi form of the ignore-previous-instructions phrase.", lang="hi"),
    Rule("ML-HI-02", "instruction_override", "override_behaviour", 9,
         r"(?:\u092a\u093f\u091b\u0932\u0947|\u0938\u092d\u0940\s+\u092a\u093f\u091b\u0932\u0947|\u090a\u092a\u0930\s+\u0915\u0947)\s+(?:\u0938\u092d\u0940\s+)?(?:\u0928\u093f\u0930\u094d\u0926\u0947\u0936|\u0906\u0926\u0947\u0936|\u0928\u093f\u092f\u092e)\S*\s+(?:\u0915\u094b\s+)?(?:\u0905\u0928\u0926\u0947\u0916\u093e|\u0928\u091c\u093c\u0930\u0905\u0902\u0926\u093e\u091c\u093c|\u0928\u091c\u0930\u0905\u0902\u0926\u093e\u091c|\u092d\u0942\u0932)",
         "Ignore-previous-instructions (Hindi)", "Devanagari form of the ignore-previous-instructions phrase.", lang="hi"),
    Rule("ML-HI-03", "info_extraction", "leak_prompt", 8,
         r"\b(?:system\s+prompt|gupt|secret|password|confidential)\s+(?:ko\s+)?(?:\w+\s+){0,2}?(?:batao|bataiye|dikhao|dikhaiye|bhejo|share\s+karo|reveal\s+karo)\b",
         "Reveal protected information (Hinglish)", "Romanised-Hindi request to reveal hidden or confidential information.", lang="hi"),
]

_COMPILED: dict[str, re.Pattern] = {r.id: re.compile(r.pattern, r.flags) for r in RULES}
RULES_BY_ID = {r.id: r for r in RULES}


@dataclass
class RuleHit:
    rule: Rule
    start: int          # original-text offsets
    end: int
    via: str            # "text" or "deobfuscated"
    intent: str


def _overlap(a0: int, a1: int, b0: int, b1: int) -> bool:
    return a0 < b1 and b0 < a1


def find_hits(doc: Doc) -> list[RuleHit]:
    """Run every rule on the normalised and the de-obfuscated view."""
    hits: list[RuleHit] = []
    for rule in RULES:
        rx = rule.compiled()
        found: list[tuple[int, int]] = []
        for m in rx.finditer(doc.norm.text):
            s, e = doc.norm.to_orig(m.start(), m.end())
            found.append((s, e))
            intent = rule.intent
            if rule.id == "ACT-01" and re.search(r"https?://|www\.", m.group(), re.I):
                intent = "exfiltrate"
            hits.append(RuleHit(rule, s, e, "text", intent))
        if doc.deobf.text != doc.norm.text:
            for m in rx.finditer(doc.deobf.text):
                s, e = doc.deobf.to_orig(m.start(), m.end())
                if any(_overlap(s, e, a, b) for a, b in found):
                    continue
                intent = rule.intent
                if rule.id == "ACT-01" and re.search(r"https?://|www\.", m.group(), re.I):
                    intent = "exfiltrate"
                hits.append(RuleHit(rule, s, e, "deobfuscated", intent))
                found.append((s, e))
    hits.sort(key=lambda h: (h.start, -h.rule.severity))
    return hits
