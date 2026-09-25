# WF2026.7253 – Malicious Google OAuth Token Revocation Callback
## Draft enhancement + red team test request

---

## 1. Background (for the red team)
Attackers put a script tag on a compromised website that points to Google's OAuth revoke URL:

`https://accounts.google.com/o/oauth2/revoke?callback=<JavaScript>`

Google returns the `callback` value wrapped as a function call, so the victim's browser runs the attacker's JavaScript. Because the script comes from a trusted Google domain, it gets past many security controls (for example, Content Security Policy allow-lists). Attackers usually hide the payload with base64 (`atob`) or other tricks.

**Goal of testing:** check whether the detection catches the different ways an attacker can write the `callback` value.

---

## 2. Draft logic (only the `callback` condition changed)

**Before**
```
(cs-uri-query="*callback=eval(atob*" OR cs_uri_query="*callback=eval(atob*")
```

**Full draft query**
```
index="network_extended"
    sourcetype IN ("bluecoat:proxysg:access:syslog", "symantec:websecurityservice:scwss-poll")
    (cs-host="accounts.google.com" OR cs_host="accounts.google.com")
    (cs-uri-query IN ("*callback=*atob(*","*callback=*atob%28*",
        "*callback=*eval(*","*callback=*eval%28*",
        "*callback=*function(*","*callback=*function%28*",
        "*callback=*settimeout*","*callback=*setinterval*",
        "*callback=*document.write*","*callback=*import(*","*callback=*import%28*",
        "*callback=*decodeuricomponent*","*callback=*unescape*",
        "*callback=*fromcharcode*","*callback=*constructor*",
        "*callback=*[*","*callback=*%5b*","*callback=*%2528*")
     OR cs_uri_query IN ("*callback=*atob(*","*callback=*atob%28*",
        "*callback=*eval(*","*callback=*eval%28*",
        "*callback=*function(*","*callback=*function%28*",
        "*callback=*settimeout*","*callback=*setinterval*",
        "*callback=*document.write*","*callback=*import(*","*callback=*import%28*",
        "*callback=*decodeuricomponent*","*callback=*unescape*",
        "*callback=*fromcharcode*","*callback=*constructor*",
        "*callback=*[*","*callback=*%5b*","*callback=*%2528*"))
    (cs-uri-path="*oauth2/revoke*" OR cs_uri_path="*oauth2/revoke*")
| `SCD_Exclusion_List("WF2026.7253.Malicious_Google_Oauth_Token_Revocation_Callback", "user")`
| `SCD_Exclusion_List_Global("src_ip", "ipv4")`
| eval
    domain_name=coalesce(cs-host, cs_host)
    , query=coalesce(cs-uri-query, cs_uri_query)
    , user_agent=coalesce(cs-user-agent, cs_user_agent)
| `SCD_Exclusion_List("WF2026.7253.Malicious_Google_Oauth_Token_Revocation_Callback", "user_agent")`
| stats
    count
    , earliest(_time) AS earliest_time
    , latest(_time) AS latest_time
    , values(sourcetype) AS sourcetype
    , values(action) AS action
    , values(dest_port) AS dest_port
    , values(domain_name) AS domain_name
    , values(query) AS query
    , values(src_ip) AS src_ip
    , values(dest_ip) AS dest_ip
    , values(http_method) AS http_method
    , sum(bytes_in) AS bytes_in
    , sum(bytes_out) AS bytes_out
    , values(user_agent) AS user_agent
    , values(vendor_product) AS vendor_product
    BY
    user
| eval
    search_name="Malicious Google Oauth Token Revocation Callback"
    , description="User [" . user . "] associated with traffic to Oauth revoke URLs. These appear to be legitimate logout URLs but are being used to obfuscate and execute malicious JavaScript code in the victim's browsers."
| convert
    timeformat="%Y-%m-%dT%H:%M:%S%z"
    ctime(earliest_time)
    , ctime(latest_time)
| `identity_normalization(user)`
```

### Techniques the draft logic covers
| Technique | Pattern(s) |
|---|---|
| `atob` inside any wrapper (`window.eval`, `self.eval`, …) | `*atob(*`, `*atob%28*` |
| `eval` without `atob` | `*eval(*`, `*eval%28*` |
| Function constructor | `*function(*`, `*function%28*` |
| Timer execution | `*settimeout*`, `*setinterval*` |
| DOM injection | `*document.write*` |
| Dynamic import | `*import(*`, `*import%28*` |
| Non-base64 decoders | `*decodeuricomponent*`, `*unescape*`, `*fromcharcode*` |
| Constructor chaining | `*constructor*` |
| Bracket-notation keyword hiding | `*[*`, `*%5b*` |
| Double URL-encoding | `*%2528*` |
| Upper/mixed case | Covered: Splunk wildcard field matching is case-insensitive |

### Notes for reviewers
- **Noise:** Legitimate JSONP callbacks are plain names (for example `myHandler`) and don't match these patterns. The path is already limited to `oauth2/revoke`. Validate with a 30-day lookback.
- **Limitation:** This is a keyword list, so obfuscation that avoids every listed keyword can still bypass it. The red team tests below are meant to find those cases.
- **Existing bug (not part of this change):** In `eval`, hyphenated fields need single quotes, for example `coalesce('cs-host', cs_host)`, `'cs-uri-query'`, and `'cs-user-agent'`. Without them, Bluecoat events get empty `domain_name`, `query`, and `user_agent`, and the `user_agent` exclusion doesn't apply to them.

---

## 3. Red team test request

**How to run each test**
- Base URL: `https://accounts.google.com/o/oauth2/revoke?callback=<value>`
- All payloads are harmless: they only print `1` in the browser console. `Y29uc29sZS5sb2coMSk=` is base64 for `console.log(1)`.
- Run each test from a machine that goes through the corporate proxy, and note the time, user, and machine.
- Unless a test says otherwise, opening the URL in a browser is enough.

### Should trigger the alert

**T1 – Baseline (eval + atob)**
The standard attacker pattern: decode a base64 payload and run it.
`callback=eval(atob('Y29uc29sZS5sb2coMSk='))`

**T2 – URL-encoded payload**
The same as T1, but with the brackets and quotes encoded, so the URL looks different in logs.
`callback=eval%28atob%28%27Y29uc29sZS5sb2coMSk%3D%27%29%29`

**T3 – Wrapped eval**
Calls eval through the window object instead of directly.
`callback=window.eval(atob('Y29uc29sZS5sb2coMSk='))`

**T4 – Function constructor**
Runs the payload by building a new function instead of using eval.
`callback=Function(atob('Y29uc29sZS5sb2coMSk='))()`

**T5 – Timer execution**
Runs the payload through a timer instead of eval.
`callback=setTimeout(atob('Y29uc29sZS5sb2coMSk='))`

**T6 – Non-base64 decoding**
Hides the payload as character codes instead of base64 (no atob).
`callback=eval(String.fromCharCode(99,111,110,115,111,108,101,46,108,111,103,40,49,41))`

**T7 – Keyword splitting**
Splits the word "eval" into pieces so it never appears in full. `%2B` is a `+` sign.
`callback=window['ev'%2B'al']('console.log(1)')`

**T8 – Constructor chaining**
Reaches the code runner through built-in objects, with no eval and no atob.
`callback=[].constructor.constructor('console.log(1)')()`

**T9 – Dynamic import**
Loads the payload as a module from inline data.
`callback=import('data:text/javascript;base64,Y29uc29sZS5sb2coMSk=')`

**T10 – Case variation**
The same as T1, written in upper case.
`callback=EVAL(ATOB('Y29uc29sZS5sb2coMSk='))`

**T11 – Parameter reordering**
Puts another parameter before `callback`.
`?token=abc&callback=eval(atob('Y29uc29sZS5sb2coMSk='))`

**T12 – Double URL-encoding**
Encodes the payload twice to get past single decoding.
`callback=eval%2528atob%2528%2527Y29uc29sZS5sb2coMSk%253D%2527%2529%2529`

**T13 – Delivery from a web page (realistic attack)**
Host a simple internal test page containing
`<script src="https://accounts.google.com/o/oauth2/revoke?callback=eval(atob('Y29uc29sZS5sb2coMSk='))"></script>`
and open that page. This is how a real victim hits it. Also check whether the page address shows up as the referrer in proxy logs.

**T14 – Blocked request**
Repeat T1 from a machine or policy where the proxy blocks the request. This checks what the `action` field shows.

### Should NOT trigger the alert (false-positive checks)

**N1 – Normal revoke call:** `?token=abc` (no callback)

**N2 – Legitimate callback name:** `callback=myHandler` and `callback=jQuery123_456`

### Gap probes (may not be detected; results show where to improve next)

**G1 – Alternate Google host:** `https://oauth2.googleapis.com/revoke?callback=eval(atob('Y29uc29sZS5sb2coMSk='))`

**G2 – POST request:** send T1's callback in the request body instead of the URL.

**G3 – Visibility check:** confirm whether the proxy decrypts (SSL-inspects) Google traffic. If it doesn't, the URL path and query aren't logged and no test can trigger the alert.

---

## 4. What to record per test
| Test | Time | User / host | Alert fired? (Y/N) | `query` populated? | `action` | Notes |
|---|---|---|---|---|---|---|
| T1 | | | | | | |
| … | | | | | | |
