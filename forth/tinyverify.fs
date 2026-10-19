\  TrustWeave .twledger v1 endpoint verifier.
\  Load after the board supplies sha256, ed25519-verify, tw-allow-image,
\  tw-refuse-image, and the ROM-provisioned tw-trusted-public-key buffer.

create tw-magic char T c, char W c, char L c, char D c,
  char G c, char R c, char 0 c, char 1 c,
create tw-trusted-public-key 32 allot
create tw-payload-digest 32 allot
create tw-image-digest 32 allot
create tw-signature-message 119 allot

variable tw-bundle
variable tw-bundle-length
variable tw-payload-length
variable tw-image
variable tw-image-length

: tw-bytes= ( address-a address-b length -- flag )
  0 ?DO
    2dup i + c@ swap i + c@ <>
    IF 2drop false unloop exit THEN
  LOOP
  2drop true ;

: tw-be32@ ( address -- u )
  dup c@ 255 and 24 lshift
  over 1+ c@ 255 and 16 lshift or
  over 2 + c@ 255 and 8 lshift or
  swap 3 + c@ 255 and or ;

: tw-field ( offset -- address )
  tw-bundle @ + ;

: tw-payload-length-valid? ( -- flag )
  8 tw-field tw-be32@ 0= IF
    12 tw-field tw-be32@ dup 536870912 u< IF
      tw-payload-length ! true
    ELSE
      drop false
    THEN
  ELSE
    false
  THEN ;

: tw-header-valid? ( -- flag )
  tw-bundle-length @ 208 < IF false exit THEN
  tw-bundle @ tw-magic 8 tw-bytes= 0= IF false exit THEN
  tw-payload-length-valid? 0= IF false exit THEN
  tw-bundle-length @ 208 - tw-payload-length @ <> IF false exit THEN
  tw-trusted-public-key 112 tw-field 32 tw-bytes= ;

: tw-payload-valid? ( -- flag )
  tw-bundle @ 208 +
  tw-payload-length @ tw-payload-digest sha256
  tw-payload-digest 16 tw-field 32 tw-bytes= ;

: tw-image-valid? ( -- flag )
  tw-image @ tw-image-length @ tw-image-digest sha256
  tw-image-digest 48 tw-field 32 tw-bytes= ;

: tw-signature-valid? ( -- flag )
  s" TrustWeave.twledger.v1" tw-signature-message swap move
  0 tw-signature-message 22 + c!
  16 tw-field tw-signature-message 23 + 32 move
  48 tw-field tw-signature-message 55 + 32 move
  80 tw-field tw-signature-message 87 + 32 move
  tw-signature-message 119
  112 tw-field 144 tw-field ed25519-verify ;

: tw-verify ( bundle-address bundle-length image-address image-length -- flag )
  tw-image-length ! tw-image ! tw-bundle-length ! tw-bundle !
  tw-header-valid? 0= IF false exit THEN
  tw-payload-valid? 0= IF false exit THEN
  tw-image-valid? 0= IF false exit THEN
  tw-signature-valid? ;

: tw-enforce ( bundle-address bundle-length image-address image-length -- )
  tw-verify IF
    tw-image @ tw-image-length @ tw-allow-image
  ELSE
    tw-refuse-image
  THEN ;
