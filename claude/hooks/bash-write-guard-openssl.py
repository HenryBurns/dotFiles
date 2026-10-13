"""What the guard knows about `openssl`, kept apart from the other tables.

openssl is not one tool. It is ~50 subcommands sharing a binary, several of
which generate keys, write certificates, re-hash a directory in place or open
a listening socket -- so there is no useful thing to say about `openssl` as a
word, and a `Bash(openssl:*)` rule would be meaningless. Everything here is
keyed on the subcommand, and within a subcommand on the exact flags.

It lives in its own file because this table grows one subcommand at a time
and would otherwise crowd out every other tool in the shared tables module.
The guard loads it the same way it loads those: by path, inside a try, with
the failure recorded rather than raised. A missing file must leave openssl
ASKING, never silently vouched -- `openssl_reads` returning False on an empty
table is what gives that property, and `_missing_openssl_ok()` pins it.

THE RULE FOR ADDING ONE. Read `openssl <sub> -help` in full and enumerate the
READ flags, never the write ones. An unlisted flag refuses, so a subcommand
that gains an output option later keeps asking until someone looks at it --
which is the direction this must fail in. The flags deliberately absent from
each entry are named in its comment, so a future reader can tell "not vetted"
from "overlooked".
"""

# Shared by every subcommand that speaks TLS. -connect names a host:port and
# -servername an SNI value; neither can open a file. The protocol selectors
# only pin a version.
#
# Absent on purpose: -keylogfile and -sess_out write the session's secrets to
# disk, -writerand writes the RNG seed file, -rand READS one (harmless, but it
# takes a path and buys nothing here), and -www/-cert/-key belong to the
# server side.
TLS_CLIENT_BOOL = {
    "-tls1", "-tls1_1", "-tls1_2", "-tls1_3", "-no_tls1", "-no_tls1_1",
    "-no_tls1_2", "-no_tls1_3", "-dtls", "-dtls1", "-dtls1_2",
    "-brief", "-quiet", "-no_ign_eof", "-ign_eof", "-showcerts", "-state",
    "-debug", "-msg", "-nbio", "-prexit", "-verify_return_error",
    "-bugs", "-no_ticket", "-status", "-tlsextdebug", "-legacy_renegotiation",
    "-no_comp", "-comp", "-allow_no_dhe_kex", "-ignore_unexpected_eof",
}
TLS_CLIENT_VALUE = {
    "-connect", "-servername", "-cipher", "-ciphersuites", "-curves",
    "-sigalgs", "-alpn", "-nextprotoneg", "-verify", "-verify_depth",
    "-verify_hostname", "-verify_email", "-verify_ip", "-port", "-host",
    "-CAfile", "-CApath", "-CAstore", "-starttls", "-name", "-timeout",
    "-max_send_frag", "-split_send_frag", "-proxy", "-nameopt",
}

# Printing options shared by the certificate-ish subcommands. -noout suppresses
# the re-encoded object, which is what makes `-noout -text` a pure report.
#
# Absent on purpose: -out and -outform write the object somewhere, and for x509
# -signkey/-key/-CA/-CAkey/-req turn it into a signing tool that MINTS a
# certificate. -checkend only sets the exit status, so it is safe, but it takes
# a value and is listed as such.
CERT_PRINT_BOOL = {
    "-noout", "-text", "-subject", "-issuer", "-dates", "-startdate",
    "-enddate", "-fingerprint", "-serial", "-email", "-hash", "-subject_hash",
    "-issuer_hash", "-ocsp_uri", "-ocspid", "-modulus", "-pubkey", "-purpose",
    "-alias", "-noout_pubkey", "-ext", "-nocert", "-dateopt", "-copy_extensions",
}
CERT_PRINT_VALUE = {
    "-in", "-inform", "-nameopt", "-certopt", "-checkend", "-digest",
    "-sha1", "-sha256", "-ext",
}

# (subcommand): (bool flags, value flags). A subcommand absent from here asks,
# which is the whole point -- `genrsa`, `req`, `enc`, `ca`, `rehash`,
# `s_server`, `passwd`, `pkcs12`, `storeutl` and `fipsinstall` all write, open
# a socket, or install state, and none will ever belong in this table.
OPENSSL_READ_FLAGS = {
    # Reads a cert (or stdin) and prints fields. The signing flags are what
    # keep this keyed per flag rather than per subcommand.
    "x509": (CERT_PRINT_BOOL, CERT_PRINT_VALUE),
    # Opens a TLS connection and reports what the peer offered. It writes
    # nothing unless given -keylogfile/-sess_out/-writerand, all absent above.
    "s_client": (TLS_CLIENT_BOOL, TLS_CLIENT_VALUE),
    # Same connection surface, run repeatedly for timings. -cert/-key are the
    # client-auth pair and read their files, but they are omitted: a benchmark
    # does not need them and they take paths.
    "s_time": (TLS_CLIENT_BOOL | {"-new", "-reuse", "-verify", "-time"},
               TLS_CLIENT_VALUE | {"-www"}),
    # Pure reports with no file output at all.
    "version": ({"-a", "-v", "-b", "-o", "-f", "-p", "-d", "-e", "-m", "-r",
                 "-c"}, set()),
    "ciphers": ({"-v", "-V", "-s", "-stdname", "-convert", "-tls1", "-tls1_1",
                 "-tls1_2", "-tls1_3", "-psk", "-srp"},
                {"-ciphersuites", "-convert"}),
    "errstr": (set(), set()),
    # Verifies a chain and reports. It takes CA material, but every such flag
    # READS -- there is no output option on this subcommand at all.
    "verify": ({"-verbose", "-show_chain", "-crl_check", "-crl_check_all",
                "-policy_check", "-explicit_policy", "-inhibit_any",
                "-inhibit_map", "-x509_strict", "-extended_crl", "-use_deltas",
                "-policy_print", "-check_ss_sig", "-trusted_first",
                "-no_alt_chains", "-partial_chain", "-ignore_critical",
                "-issuer_checks", "-crl_download", "-suiteB_128_only",
                "-suiteB_128", "-suiteB_192"},
               {"-CAfile", "-CApath", "-CAstore", "-trusted", "-untrusted",
                "-CRLfile", "-purpose", "-policy", "-verify_name",
                "-verify_depth", "-auth_level", "-attime", "-verify_hostname",
                "-verify_email", "-verify_ip", "-nameopt", "-engine"}),
    # Parses DER/PEM structure and prints it. -out WRITES the parsed section
    # to a file and -genconf reads a config that directs generation, so both
    # are absent; -oid reads an OID file, also absent for taking a path we
    # gain nothing from.
    "asn1parse": ({"-noout", "-i", "-dump", "-strictpem"},
                  {"-in", "-inform", "-offset", "-length", "-strparse",
                   "-dlimit", "-item"}),
    # Benchmarks algorithms in memory. The positional names an algorithm, and
    # there is no output flag.
    "speed": ({"-decrypt", "-aead", "-mb", "-mr", "-multi", "-misalign",
               "-elapsed", "-primes", "-seconds", "-bytes", "-async_jobs"},
              {"-evp", "-hmac", "-cmac", "-mac", "-multi", "-seconds",
               "-bytes", "-primes", "-async_jobs", "-provider", "-propquery"}),
}
