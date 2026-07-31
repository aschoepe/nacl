#!/usr/bin/tclsh8.6
# Test fuer jwt-hs256.tcl. Kein Server, keine DB, kein Netz:
#   tclsh8.6 jwt-hs256-test.tcl

source [file join [file dirname [info script]] jwt-hs256.tcl]

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
proc throws {label script {muster *}} {
    global failed
    # uplevel #0: das Skript muss im globalen Kontext laufen, sonst sieht es die
    # Testvariablen nicht und scheitert an "no such variable" statt an dem
    # Fehler, um den es geht - ein Test, der aus dem falschen Grund besteht.
    if {![catch {uplevel #0 $script} e]} {
        incr failed ; puts "  FAIL $label (kein Fehler geworfen)"
    } elseif {[string match $muster $e]} {
        puts "  ok   $label"
    } else {
        incr failed ; puts "  FAIL $label (falscher Fehler: $e)"
    }
}

# Fremdes Token, nicht von diesem Modul erzeugt: der Standardvektor von jwt.io.
# Er belegt, dass die Signatur mit anderen Implementierungen uebereinstimmt.
set fremd {eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c}
set fremdSecret {your-256-bit-secret}

puts "\n--- fremdes Token (Interoperabilitaet)"
check "Secret ist kuerzer als 32 Byte" [string length $fremdSecret] 19
check "verify liefert den Payload" \
    [string match {*"name":"John Doe"*} [::jwt::verify $fremd $fremdSecret -time 0]] 1
throws "falsches Secret" {::jwt::verify $fremd "wrong-secret" -time 0} "*bad signature*"

puts "\n--- Schluessellaengen"
# Genau der Bereich, der ohne die RFC-2104-Vorbereitung nicht erreichbar war.
foreach n {1 19 31 32 33 64 65 131} {
    set secret [string repeat A $n]
    set t [::jwt::sign {{"sub":"1234"}} $secret]
    check "Laenge $n Byte" [::jwt::verify $t $secret -time 0] {{"sub":"1234"}}
}

puts "\n--- Manipulation"
set secret [string repeat A 64]
set t [::jwt::sign {{"sub":"1234"}} $secret]
lassign [split $t .] h p s

throws "veraenderter Payload" {
    ::jwt::verify $h.[::jwt::b64url {{"sub":"admin"}}].$s $secret -time 0
} "*bad signature*"
# Ein BYTE der Signatur kippen, nicht ein base64-Zeichen: 32 Byte belegen 43
# base64url-Zeichen, das letzte davon traegt zwei Fuellbits, die beim Dekodieren
# wegfallen. Ein geaendertes letztes Zeichen kann also dieselbe Signatur ergeben
# und wuerde einen Test vortaeuschen, der nichts prueft.
binary scan [::jwt::unb64url $s] cu* sigBytes
lset sigBytes 0 [expr {[lindex $sigBytes 0] ^ 0xff}]
set sKaputt [::jwt::b64url [binary format cu* $sigBytes]]
throws "gekipptes Byte in der Signatur" {
    ::jwt::verify $h.$p.$sKaputt $secret -time 0
} "*bad signature*"
throws "gekuerzte Signatur" {::jwt::verify $h.$p.[string range $s 0 20] $secret -time 0} \
    "*bad signature*"
throws "leere Signatur" {::jwt::verify $h.$p. $secret -time 0} "*malformed*"
throws "nur zwei Teile" {::jwt::verify $h.$p $secret -time 0} "*malformed*"
throws "vier Teile" {::jwt::verify $h.$p.$s.$s $secret -time 0} "*malformed*"

puts "\n--- alg wird nicht vom Token bestimmt"
# "alg":"none" mit leerer Signatur - der Klassiker.
set noneHeader [::jwt::b64url {{"alg":"none","typ":"JWT"}}]
throws "alg none" {::jwt::verify $noneHeader.$p.$s $secret -time 0} "*unexpected alg*"
# Header behauptet HS512, geprueft wird HS256.
set hs512Header [::jwt::b64url {{"alg":"HS512","typ":"JWT"}}]
throws "alg HS512 im Header" {::jwt::verify $hs512Header.$p.$s $secret -time 0} \
    "*unexpected alg*"
throws "HS512 angefordert" {::jwt::verify $t $secret -alg HS512 -time 0} "*only HS256*"

puts "\n--- Zeitpruefung"
set abgelaufen [::jwt::sign {{"sub":"1234","exp":1000}} $secret]
throws "exp in der Vergangenheit" {::jwt::verify $abgelaufen $secret -now 2000} "*expired*"
check "exp in der Zukunft" \
    [::jwt::verify $abgelaufen $secret -now 500] {{"sub":"1234","exp":1000}}
check "leeway deckt knappen Ablauf ab" \
    [::jwt::verify $abgelaufen $secret -now 1005 -leeway 30] {{"sub":"1234","exp":1000}}

set nochNicht [::jwt::sign {{"sub":"1234","nbf":5000}} $secret]
throws "nbf in der Zukunft" {::jwt::verify $nochNicht $secret -now 4000} "*not yet valid*"
check "nbf erreicht" [::jwt::verify $nochNicht $secret -now 5000] {{"sub":"1234","nbf":5000}}

check "ohne exp und nbf gilt das Token" \
    [::jwt::verify $t $secret -now 999999999] {{"sub":"1234"}}

puts "\n--- base64url"
check "kein +, / oder = im Token" [regexp {[+/=]} $t] 0
check "Roundtrip mit Padding-Bedarf" \
    [::jwt::unb64url [::jwt::b64url [binary format H* "01"]]] [binary format H* "01"]

puts ""
if {$failed} {
    puts "$failed Test(s) fehlgeschlagen"
    exit 1
}
puts "alle Tests bestanden"
