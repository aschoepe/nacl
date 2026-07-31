#!/usr/bin/tclsh8.6
# Test fuer secretbox-store.tcl. Kein Server, keine DB, keine Config:
#   tclsh8.6 secretbox-store-test.tcl

source [file join [file dirname [info script]] secretbox-store.tcl]

set failed 0
proc check {label got want} {
    global failed
    if {$got eq $want} {
        puts "  ok   $label"
    } else {
        incr failed
        puts "  FAIL $label\n       got:  $got\n       want: $want"
    }
}
proc throws {label script} {
    global failed
    # uplevel #0: ohne das laeuft $script im Kontext dieser Prozedur, sieht die
    # Testvariablen nicht und scheitert an "no such variable" - der Test bestuende
    # dann aus dem falschen Grund und pruefte in Wahrheit nichts.
    if {[catch {uplevel #0 $script}]} {
        puts "  ok   $label"
    } else {
        incr failed ; puts "  FAIL $label (kein Fehler geworfen)"
    }
}

set key  [::secretbox::unb64url [::secretbox::newKey]]
set key2 [::secretbox::unb64url [::secretbox::newKey]]

puts "\n--- Schluessel"
check "newKey liefert 32 Byte" [string length $key] 32
check "zwei Schluessel sind verschieden" [expr {$key ne $key2}] 1

puts "\n--- base64url"
set bin [binary format H* "fbff3e"]
check "kein +, / oder = im Ergebnis" [regexp {[+/=]} [::secretbox::b64url $bin]] 0
check "Roundtrip" [::secretbox::unb64url [::secretbox::b64url $bin]] $bin
check "Roundtrip mit Padding-Bedarf" \
    [::secretbox::unb64url [::secretbox::b64url [binary format H* "01"]]] [binary format H* "01"]

puts "\n--- Roundtrip"
set blob [::secretbox::encrypt "hunter2" $key]
check "Praefix enc:" [::secretbox::isEnc $blob] 1
check "Klartext taucht NICHT im Blob auf" [string match *hunter2* $blob] 0
check "entschluesselt wieder gleich" [::secretbox::decrypt $blob $key] "hunter2"
check "leerer Klartext geht auch" [::secretbox::decrypt [::secretbox::encrypt "" $key] $key] ""
# Umlaute als \uXXXX, nicht literal: auf einem System mit iso8859-1-Default-
# Encoding (Debian + LANG=C) liest Tcl den Quelltext anders als der Editor ihn
# geschrieben hat - der Test wuerde dann etwas anderes pruefen, als dasteht.
set umlaut "Gr\u00fc\u00dfe"
check "Umlaute/UTF-8 ueberleben" [::secretbox::decrypt [::secretbox::encrypt $umlaut $key] $key] $umlaut
check "langer Wert" \
    [string length [::secretbox::decrypt [::secretbox::encrypt [string repeat x 5000] $key] $key]] 5000

puts "\n--- Nonce: zweimal dasselbe ergibt VERSCHIEDENE Blobs"
set a [::secretbox::encrypt "gleich" $key]
set b [::secretbox::encrypt "gleich" $key]
check "Blobs unterscheiden sich" [expr {$a ne $b}] 1
check "beide entschluesseln zum selben Klartext" \
    [expr {[::secretbox::decrypt $a $key] eq [::secretbox::decrypt $b $key]}] 1

puts "\n--- Authentizitaet (secretbox ist authentifiziert - kein stiller Muell)"
throws "falscher Schluessel schlaegt fehl" { ::secretbox::decrypt $blob $key2 }
# Ein Byte in der Chiffre kippen: der MAC muss anschlagen.
set raw [::secretbox::unb64url [string range $blob 4 end]]
set tampered [string replace $raw 30 30 [binary format c [expr {([scan [string index $raw 30] %c] ^ 1) & 0xff}]]]
throws "manipulierte Chiffre schlaegt fehl" \
    { ::secretbox::decrypt "enc:[::secretbox::b64url $tampered]" $key }

puts "\n--- Formatfehler"
throws "Klartext ohne enc: wird abgewiesen" { ::secretbox::decrypt "hunter2" $key }
throws "zu kurzer Blob wird abgewiesen" { ::secretbox::decrypt "enc:AAAA" $key }
throws "Schluessel mit falscher Laenge" { ::secretbox::encrypt "x" "zu-kurz" }
check "isEnc auf Klartext" [::secretbox::isEnc "plain"] 0
check "isEnc auf leerem Wert" [::secretbox::isEnc ""] 0

puts ""
if {$failed} { puts "$failed FAILED" ; exit 1 }
puts "alle Tests bestanden"
