\ Execute the real TinyVerify Forth definitions with deterministic host stubs.
\ Cryptographic primitive correctness is tested separately by the Rust bundle tests.

variable host-signature-result
variable host-allowed
variable host-hash-source
variable host-hash-length
variable host-hash-destination
variable host-hash-sum

create host-digest 32 allot
create host-bundle 211 allot
create host-image 3 allot

: sha256 ( address length digest-address -- )
  host-hash-destination !
  host-hash-length !
  host-hash-source !
  0 host-hash-sum !
  host-hash-length @ 0 ?DO
    host-hash-sum @ host-hash-source @ i + c@ +
    host-hash-sum !
  LOOP
  host-hash-destination @ 32 0 fill
  host-hash-sum @ host-hash-destination @ c! ;

: ed25519-verify ( message-address message-length public-key signature -- flag )
  2drop 2drop host-signature-result @ ;

: tw-allow-image ( image-address image-length -- )
  2drop true host-allowed ! ;

: tw-refuse-image ( -- )
  false host-allowed ! ;

include tinyverify.fs

: host-assert ( flag -- )
  0= IF -1 throw THEN ;

: host-prepare-bundle ( -- )
  host-bundle 211 0 fill
  tw-magic host-bundle 8 move
  3 host-bundle 15 + c!
  s" abc" host-bundle 208 + swap move
  host-bundle 208 + 3 host-digest sha256
  host-digest host-bundle 16 + 32 move
  s" xyz" host-image swap move
  host-image 3 host-digest sha256
  host-digest host-bundle 48 + 32 move ;

: host-test-valid ( -- )
  host-prepare-bundle
  true host-signature-result !
  false host-allowed !
  host-bundle 211 host-image 3 tw-enforce
  host-allowed @ host-assert ;

: host-test-payload-tamper ( -- )
  host-prepare-bundle
  host-bundle 208 + c@ 1 xor host-bundle 208 + c!
  true host-signature-result !
  false host-allowed !
  host-bundle 211 host-image 3 tw-enforce
  host-allowed @ 0= host-assert ;

: host-test-image-tamper ( -- )
  host-prepare-bundle
  host-image c@ 1 xor host-image c!
  true host-signature-result !
  false host-allowed !
  host-bundle 211 host-image 3 tw-enforce
  host-allowed @ 0= host-assert ;

: host-test-signature-failure ( -- )
  host-prepare-bundle
  false host-signature-result !
  false host-allowed !
  host-bundle 211 host-image 3 tw-enforce
  host-allowed @ 0= host-assert ;

: host-test-truncated-header ( -- )
  host-prepare-bundle
  true host-signature-result !
  false host-allowed !
  host-bundle 207 host-image 3 tw-enforce
  host-allowed @ 0= host-assert ;

: host-test-untrusted-signer ( -- )
  host-prepare-bundle
  1 host-bundle 112 + c!
  true host-signature-result !
  false host-allowed !
  host-bundle 211 host-image 3 tw-enforce
  host-allowed @ 0= host-assert ;

host-test-valid
host-test-payload-tamper
host-test-image-tamper
host-test-signature-failure
host-test-truncated-header
host-test-untrusted-signer
." TinyVerify Forth sandbox tests passed (cryptographic stubs only)." cr
bye
