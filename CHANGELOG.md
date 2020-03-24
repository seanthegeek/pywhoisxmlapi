2.1.6
-----

- Fix basic WHOIS lookup on the CLI
- Remove more duplicated code

2.1.5
-----

- Fix reverse WHOIS preview
- Simplify bulk the bulk WHOIS lookup CLI
- Remove duplicated code

2.1.4
-----

- Fix reverse WHOIS preview

2.1.3
-----

- Output purchased reverse WHOIS searches as a simple list of domains instead of JSON

2.1.2
-----

- Fix historic reverse WHOIS searches

2.1.1
-----

- Fix CSV output of WHOIS records with fax fields

2.1.0
-----

- Add `flatten_whois()` and `whois_to_csv()`

2.0.3
-----

- Fix bulk WHOIS
- Add netblocks API

2.0.2
-----

- More documentation formatting fixes

2.0.1
-----

- Fix documentation formatting


2.0.0
-----

- Fix requests compatibility
- Use correct HTTP API endpoint for registrant alerts
- Add all date options to brand and registrant alert methods 
- Add the following subcommands to the CLI:
  - `history`
  - `registrant`
  - `reverse-ip`
  - `reverse-mx`
  - `reverse-ns`

1.0.1
-----
- Fix `<exclude_terms>` in CLI
- Unify package, module, and CLI versions

1.0.0
-----
- Initial release