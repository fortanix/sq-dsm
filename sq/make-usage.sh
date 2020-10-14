#!/bin/sh

tool=$1

quote() {
    sed 's@^@//! @' | sed 's/ $//'
}

begin_code() {
    printf '```text\n'
}

end_code() {
    printf '```\n'
}

dump_help() { # subcommand, indentation
    if [ -z "$1" ]
    then
	printf "\n# Usage\n\n"
        set "" "#"
    else
	printf "\n$2 Subcommand$1\n\n"
    fi

    help="`$tool $1 --help`"

    begin_code
    printf "$help\n" | tail -n +2
    end_code

    if echo $help | fgrep -q SUBCOMMANDS
    then
        printf "$help\n" |
            sed -n '/^SUBCOMMANDS:/,$p' |
	    tail -n+2 |
	    grep '^    [^ ]' |
	    while read subcommand desc
	    do
	        if [ "$subcommand" = help ]; then
		    continue
	        fi

                dump_help "$1 $subcommand" "#$2"
	    done
    fi
}

(
    printf "A command-line frontend for Sequoia.\n"
    dump_help
) | quote

printf '\ninclude!("'"$(basename $tool)"'.rs");\n'
