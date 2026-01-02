#!/bin/sh
#\
exec tclsh "$0" "$@"

#
# 2024-2025 Alexander Schöpe, Bochum, DE
# mkversion.c from fossil-scm ported to vanilla tcl
#

set manifest {}
set optDefines 0
set optPkgName 0
set pkgName {}


# Note:
# fossil GUI Settings Manifest = on.
# If necessary, the fossil clone setting 'fossil settings manifest --value' must be checked
# and set correctly using 'fossil settings manifest on'.

proc hash {zIn N} {
  set zL {}
  foreach c [split $zIn {}] {
    lappend zL [scan $c %c]
  }
  lappend zL 0
  set zIn $zL
  unset zL

  set s {}
  for {set m 0} {$m < 256} {incr m} {
    lappend s $m
  }
  lappend s 0

  for {set t 0; set j 0; set n 0; set m 0} {$m < 256} {incr m; incr n} {
    set j [expr {($j + [lindex $s $m] + [lindex $zIn $n]) & 0xff}]
    if {[lindex $zIn $n] == 0} {
      set n -1
    }
    set t [lindex $s $j]
    set s [lreplace $s $j $j [lindex $s $m]]
    set s [lreplace $s $m $m $t]
  }

  set i 0
  set j 0
  set zOut {}
  for {set n 0} {$n < $N-2} {incr n 2} {
    incr i
    set t [lindex $s $i]
    set j [expr {($j + $t) & 0xff}]
    set s [lreplace $s $i $i [lindex $s $j]]
    set s [lreplace $s $j $j $t]
    set t [expr {($t + [lindex $s $i]) & 0xff}]
    append zOut [string index 0123456789abcdef [expr {($t >> 4) & 0xf}]]
    append zOut [string index 0123456789abcdef [expr {$t & 0xf}]]
  }

  return $zOut
}

if {![catch {open manifest.uuid r} fd]} {
  if {![eof $fd]} {
    if {[gets $fd uuid] > 0} {
      lappend manifest MANIFEST_UUID $uuid
      lappend manifest MANIFEST_VERSION [format {%10.10s} $uuid]
      if {[info exists ::env(SOURCE_DATE_EPOCH)] && [string is wideinteger $::env(SOURCE_DATE_EPOCH)]} {
        set ctime $::env(SOURCE_DATE_EPOCH)
      } else {
        set ctime [clock seconds]
      }
      append uuid $ctime
      lappend manifest FOSSIL_BUILD_HASH [hash $uuid 33]
    }
  }
  close $fd
} else {
  puts stderr "can't open file manifest.uuid"
}

if {![catch {open manifest r} fd]} {
  while {![eof $fd]} {
    if {[gets $fd line] > 0} {
      if {[string match {D *} $line]} {
	set ctime [clock scan [lindex [split [lindex $line 1] .] 0] -gmt 1]
	lappend manifest MANIFEST_DATE [clock format $ctime -format {%Y-%m-%d %H:%M:%S} -gmt 1]
	lappend manifest MANIFEST_YEAR [clock format $ctime -format {%Y} -gmt 1]
	lappend manifest MANIFEST_NUMERIC_DATE [clock format $ctime -format {%Y%m%d} -gmt 1]
	lappend manifest MANIFEST_NUMERIC_TIME [clock format $ctime -format {%H%M%S} -gmt 1]
	break
      }
    }
  }
  close $fd
} else {
  puts stderr "can't open file manifest"
}

if {![catch {open configure.ac r} fd]} {
  while {![eof $fd]} {
    if {[gets $fd line] > 0} {
      if {[string match {AC_INIT*} $line]} {
	if {[regexp {AC_INIT\(\[([^\]]*)\]\s*,\s*\[(.*?)\]\)} $line match name version]} {
	  set pkgName [string toupper $name]
	  set versionList [lrange [split $version.0.0.0 .] 0 3]
	  lappend manifest RELEASE_VERSION $version
	  lappend manifest RELEASE_VERSION_NUMBER [format {%d%02d%d%d} {*}$versionList]
	  lappend manifest RELEASE_RESOURCE_VERSION [format {%d,%d,%d,%d} {*}$versionList]
	}
	break
      }
    }
  }
  close $fd
} else {
  puts stderr "can't open file configure.ac"
}

if {0} {
#
# Build Info Example Procedure
#

proc ::pkgname::build-info { {cmd {}} } {
  variable pkgPath

  # TIP 599: Extended build information
  # https://core.tcl-lang.org/tips/doc/trunk/tip/599.md

  set file [file join $pkgPath manifest.txt]

  if {[file readable $file] && ![catch {open $file r} fd]} {
    set manifest [read $fd]
    close $fd

    set uuid [dict get $manifest MANIFEST_UUID]
    set checkin [string map {[ {} ] {}} [dict get $manifest MANIFEST_VERSION]]
    set build [dict get $manifest FOSSIL_BUILD_HASH]
    set datetime [string map {{ } T} [dict get $manifest MANIFEST_DATE]]Z
    set version [dict get $manifest RELEASE_VERSION]
    set compiler {tcl.noarch}

    switch -- $cmd {
      commit {
        return $uuid
      }
      version - patchlevel {
        return $version
      }
      compiler {
        return $compiler
      }
      path {
        return $pkgPath
      }
      default {
        return ${version}+${checkin}.${datetime}.${compiler}
      }
    }
  } else {
    return {?.manifest_not_found}
  }
}

package provide 1.0

# info script ?filename?
# If a Tcl script file is currently being evaluated (i.e. there is a call to Tcl_EvalFile active or there is an active invocation of the source command),
# then this command returns the name of the innermost file being processed. If filename is specified, then the return value of this command will be modified
# for the duration of the active invocation to return that name. This is useful in virtual file system applications. Otherwise the command returns an empty string.
set ::pkgname::pkgPath [file dirname [info script]]
}

foreach arg $argv {
  switch -exact -- $arg {
    -defines {
      set optDefines 1
    }
    -name {
      set optPkgName 1
    }
  }
}

if {$optDefines} {
  foreach {n v} $manifest {
    if {$n ni {MANIFEST_NUMERIC_DATE MANIFEST_NUMERIC_TIME RELEASE_VERSION_NUMBER RELEASE_RESOURCE_VERSION}} {
      set v "\"$v\""
    }
    if {$optPkgName && $pkgName ne {}} {
      puts "#define ${pkgName}_${n} $v"
    } else {
      puts "#define $n $v"
    }
  }
} else {
  foreach {n v} $manifest {
    if {$optPkgName && $pkgName ne {}} {
      puts [list ${pkgName}_${n} $v]
    } else {
      puts [list $n $v]
    }
  }
}
