# jwt-hs256.tcl -- JSON Web Token mit HS256 pruefen und erzeugen.
#
# UEBERNEHMEN, NICHT NACHBAUEN. Getestet: jwt-hs256-test.tcl
# (tclsh8.6 jwt-hs256-test.tcl, kein Server, keine DB).
#
# Format:  base64url(header) "." base64url(payload) "." base64url(signature)
#          Signatur = HMAC-SHA-256 ueber die ersten beiden Teile SAMT Punkt.
#
# Das Secret wird HEREINGEREICHT und in seiner urspruenglichen Laenge benutzt.
# nacl::auth bereitet es nach RFC 2104 auf, deshalb darf es 19, 32 oder 64 Byte
# lang sein - selbst auffuellen oder vorher hashen ergibt einen ANDEREN Tag, den
# keine Gegenstelle bestaetigt.
#
# NUR HS256. Was nacl unter -hmac512256 anbietet, ist HMAC-SHA-512 auf 32 Byte
# gekuerzt und damit NICHT das HS512 aus RFC 7518 (das 64 Byte Tag verlangt).
# Wer HS384/HS512 braucht, nimmt eine andere Bibliothek - ein gekuerzter Tag,
# der als HS512 ausgegeben wird, ist ein stiller Interoperabilitaetsfehler.
#
# Die drei Wege, auf denen eine JWT-Pruefung ueblicherweise scheitert, und was
# dieses Modul dagegen tut:
#
#   1. "alg" aus dem Token uebernehmen. Der Header wird vom ABSENDER geliefert.
#      Wer daraus ableitet, wie geprueft wird, laesst sich vom Angreifer die
#      Pruefmethode diktieren - "alg":"none" haengt einfach eine leere Signatur
#      an. Hier wird der ERWARTETE Algorithmus hereingereicht und der Header
#      dagegen geprueft, nie umgekehrt.
#   2. Tags mit == oder "string equal" vergleichen. Das bricht beim ersten
#      abweichenden Byte ab und verraet ueber die Laufzeit, wie weit man war.
#      Hier vergleicht nacl::auth verify in konstanter Zeit.
#   3. Signatur pruefen und fertig. Ein gueltig signiertes Token kann Jahre alt
#      sein. exp und nbf gehoeren dazu, sonst gilt ein abgelaufenes Token weiter.
#
# JSON: dieses Modul liest nur "alg", "exp" und "nbf" heraus, und zwar mit einem
# absichtlich winzigen Extraktor - die drei Felder sind Zahlen bzw. ein kurzer
# String ohne Escapes. Fuer die eigentlichen Claims des Payloads gehoert ein
# echter JSON-Parser her (tcllib json, rl_json); verify gibt den Payload roh
# zurueck, damit die Anwendung das mit ihrem Parser tut.

package require Tcl 8.6-
package require nacl

namespace eval ::jwt {
    namespace export b64url unb64url sign verify
}

# --- base64url ---------------------------------------------------------------

proc ::jwt::b64url {bin} {
    string map {+ - / _ = {}} [binary encode base64 $bin]
}

proc ::jwt::unb64url {s} {
    # base64url laesst das "="-Padding weg, binary decode base64 braucht es.
    set s [string map {- + _ /} $s]
    while {[string length $s] % 4} { append s = }
    return [binary decode base64 $s]
}

# --- winziger Feldleser ------------------------------------------------------

# Stringfeld, z.B. "alg":"HS256". Bewusst ohne Escape-Behandlung: fuer alg
# genuegt es, und alles darueber hinaus gehoert in einen JSON-Parser.
proc ::jwt::_str {json name} {
    if {[regexp "\"$name\"\\s*:\\s*\"(\[^\"\]*)\"" $json -> v]} {
        return $v
    }
    return ""
}

# Zahlenfeld, z.B. "exp":1516239022
proc ::jwt::_num {json name} {
    if {[regexp "\"$name\"\\s*:\\s*(-?\\d+)" $json -> v]} {
        return $v
    }
    return ""
}

# --- erzeugen ----------------------------------------------------------------

# Token aus einem fertigen Payload-JSON bauen. Der Header wird hier geschrieben
# und nicht vom Aufrufer uebernommen, damit alg und typ nicht auseinanderlaufen.
proc ::jwt::sign {payloadJson secret} {
    set signingInput [b64url {{"alg":"HS256","typ":"JWT"}}].[b64url $payloadJson]
    if {[nacl::auth -hmac256 tag $signingInput $secret] != 0} {
        error "jwt: HMAC failed"
    }
    return $signingInput.[b64url $tag]
}

# --- pruefen -----------------------------------------------------------------

# Gibt den Payload als rohen JSON-String zurueck oder wirft einen Fehler.
#
#   -alg     erwarteter Algorithmus (Vorgabe HS256). Der Header muss ihn nennen.
#   -now     Zeitpunkt fuer exp/nbf (Vorgabe [clock seconds]); fuer Tests.
#   -leeway  erlaubte Uhrendifferenz in Sekunden (Vorgabe 0).
#   -time    0 schaltet die Zeitpruefung ab (nur wenn die Anwendung sie selbst
#            macht - die Vorgabe ist an).
proc ::jwt::verify {token secret args} {
    array set opt {-alg HS256 -now {} -leeway 0 -time 1}
    array set opt $args
    if {$opt(-now) eq {}} { set opt(-now) [clock seconds] }

    if {$opt(-alg) ne "HS256"} {
        error "jwt: only HS256 is supported, not $opt(-alg)"
    }

    # Genau drei Teile. Ein zweiteiliges Token ist eine unsignierte Behauptung.
    set parts [split $token .]
    if {[llength $parts] != 3} {
        error "jwt: malformed token"
    }
    lassign $parts h p s
    if {$h eq {} || $p eq {} || $s eq {}} {
        error "jwt: malformed token"
    }

    set header [unb64url $h]
    set payload [unb64url $p]
    set sig [unb64url $s]

    # Erwarteten Algorithmus gegen den Header pruefen - nicht den Header
    # entscheiden lassen. Faengt "none" und den Wechsel auf ein anderes
    # Verfahren in einem Schritt ab.
    set alg [_str $header alg]
    if {$alg ne $opt(-alg)} {
        error "jwt: unexpected alg \"$alg\", expected $opt(-alg)"
    }

    # Laenge vor dem Vergleich pruefen: nacl::auth verify verlangt genau 32 Byte
    # und wuerde bei einer gekuerzten Signatur einen Tcl-Fehler werfen statt sie
    # sauber abzulehnen.
    if {[string length $sig] != 32} {
        error "jwt: bad signature"
    }

    # Konstante Zeit. $h.$p ist der signierte Text - mit dem Punkt, und in der
    # Schreibweise, wie sie ankam (nicht neu kodiert).
    if {[nacl::auth verify -hmac256 $sig $h.$p $secret] != 0} {
        error "jwt: bad signature"
    }

    if {$opt(-time)} {
        set now $opt(-now)
        set exp [_num $payload exp]
        if {$exp ne {} && $now >= ($exp + $opt(-leeway))} {
            error "jwt: token expired"
        }
        set nbf [_num $payload nbf]
        if {$nbf ne {} && $now < ($nbf - $opt(-leeway))} {
            error "jwt: token not yet valid"
        }
    }

    return $payload
}
