// Owner-supplied registrations. Exact host matches only: no suffix or IP guesses.
// No passwords, panel credentials or SSO sessions belong in this directory.
const registrations = [
  { hostname: 'kinglaminaat.nl', server: 'S01', provider: 'Interfile',
    source: 'User report, confirmed with a colleague', recordedAt: '2026-09-14' },
];

export function lookupRegistration(hostname) {
  const host = String(hostname || '').trim().toLowerCase().replace(/\.$/, '');
  const record = registrations.find(item => item.hostname === host);
  return record
    ? { ...record, state: 'registered', method: 'manual', location: null, asn: null }
    : { hostname: host, state: 'unmapped', server: null, provider: null,
        source: null, recordedAt: null, method: null, location: null, asn: null };
}
