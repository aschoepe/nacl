# secretbox-store.tcl -- Geheimnisse VERSCHLUESSELT in Konfig-/Datendateien
# ablegen und wieder lesen (SMTP-Passwoerter, API-Keys, TOTP-Secrets).
#
# UEBERNEHMEN, NICHT NACHBAUEN. Getestet: secretbox-store-test.tcl
# (tclsh8.6 secretbox-store-test.tcl, kein Server, keine DB).
#
# Speicherformat:   enc:base64url( nonce(24) || secretbox-cipher )
#                   (xsalsa20-poly1305, authentifiziert)
#
# Warum ein Praefix und base64url:
#   - `enc:` macht Klartext und Chiffre in EINER Datei unterscheidbar. Ohne den
#     Marker muss jeder Leser raten, ob ein Wert schon verschluesselt ist - und
#     eine Migration (erst Klartext, spaeter verschluesselt) wird unmoeglich.
#   - base64url (keine + / =) ueberlebt JSON, URLs, Shell und Copy-Paste, ohne
#     dass jemand escapen muss.
#
# Der Schluessel wird HEREINGEREICHT (32 Byte, roh). Woher er kommt - Config,
# Datei, Umgebungsvariable - entscheidet die Anwendung, nicht dieses Modul.
#
# Sicherheitsgrenze: Wer die Schluesseldatei lesen kann, kann entschluesseln.
# Der Schutz ist der DATEIZUGRIFF (Web-403 auf das Konfig-Verzeichnis,
# restriktive Permissions, Schluessel ausserhalb des DocumentRoot), nicht die
# Frage, ob Schluessel und Chiffre in derselben Datei stehen.

package require Tcl 8.6-
package require nacl

namespace eval ::secretbox {
    namespace export b64url unb64url isEnc encrypt decrypt newKey
}

# --- base64url ---------------------------------------------------------------
proc ::secretbox::b64url {bin} {
    string map {+ - / _ = {}} [binary encode base64 $bin]
}

proc ::secretbox::unb64url {s} {
    set s [string map {- + _ /} $s]
    # Padding wieder anhaengen: binary decode base64 braucht die Laenge % 4 == 0,
    # base64url laesst die "=" aber weg.
    while {[string length $s] % 4} { append s = }
    return [binary decode base64 $s]
}

# --- Schluessel --------------------------------------------------------------

# Neuen 32-Byte-Schluessel erzeugen (base64url, direkt in die Config kopierbar).
# NIE selbst wuerfeln (rand(), clock, /dev/urandom von Hand) - die Plattform hat
# einen CSPRNG, und ein nachgebauter ist der Klassiker unter den Kryptofehlern.
proc ::secretbox::newKey {} {
    return [b64url [nacl::randombytes secretbox -key]]
}

# --- Erkennen ----------------------------------------------------------------

# Ist der Wert bereits ein enc:-Blob? Damit laesst sich eine Datei mischen
# (Klartext + Chiffre) und schrittweise migrieren.
proc ::secretbox::isEnc {v} {
    expr {[string range $v 0 3] eq {enc:}}
}

# --- Ver-/Entschluesseln -----------------------------------------------------

# Klartext -> enc:base64url(nonce||cipher).
#
# Die Nonce wird JEDES MAL neu gezogen und VOR die Chiffre gelegt - sie ist kein
# Geheimnis, aber sie darf sich mit demselben Schluessel nie wiederholen. Wer
# eine feste Nonce nimmt (oder einen Zaehler ohne Persistenz), hebelt die
# Verschluesselung aus: gleiche Nonce + gleicher Key = gleicher Keystream.
proc ::secretbox::encrypt {plaintext key} {
    if {[string length $key] != 32} {
        error "secretbox::encrypt: Schluessel muss 32 Byte sein (roh, nicht base64)"
    }
    set nonce [nacl::randombytes secretbox -nonce]
    # nacl schreibt das Ergebnis in eine VARIABLE (hier: cipher) und liefert
    # 0/!=0 als Status - nicht die Chiffre. Wer den Rueckgabewert als Daten
    # nimmt, verschluesselt "0".
    if {[nacl::secretbox cipher $plaintext $nonce $key] != 0} {
        error "secretbox::encrypt: nacl::secretbox failed"
    }
    return "enc:[b64url ${nonce}${cipher}]"
}

# enc:base64url(nonce||cipher) -> Klartext. Wirft bei Formatfehler UND bei
# falschem Schluessel/manipulierter Chiffre (secretbox ist authentifiziert -
# der MAC schlaegt an, es kommt kein Muell zurueck).
proc ::secretbox::decrypt {blob key} {
    if {![isEnc $blob]} { error "secretbox::decrypt: kein enc:-Wert" }
    if {[string length $key] != 32} {
        error "secretbox::decrypt: Schluessel muss 32 Byte sein (roh, nicht base64)"
    }
    set bin [unb64url [string range $blob 4 end]]
    # 24 Byte Nonce + 16 Byte MAC = 40; ein leerer Klartext ergaebe 40, alles
    # darunter ist kaputt. Ohne diese Pruefung liefert string range stillen
    # Unsinn statt eines Fehlers.
    if {[string length $bin] < 40} {
        error "secretbox::decrypt: zu kurz (nonce+cipher mindestens 40 Byte)"
    }
    set nonce  [string range $bin 0 23]
    set cipher [string range $bin 24 end]
    if {[nacl::secretbox open plain $cipher $nonce $key] != 0} {
        error "secretbox::decrypt: secretbox open failed (falscher Schluessel oder manipuliert)"
    }
    return $plain
}

package provide secretbox 1.0
