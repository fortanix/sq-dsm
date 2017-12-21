#!/bin/sh

quote() {
    sed 's@^@//! @' | sed 's/ $//'
}

begin_code() {
    printf '```text\n'
}

end_code() {
    printf '```\n'
}

(
    printf "A command-line frontend for Sequoia.

# Usage

"
    begin_code
    sq --help
    end_code

    sq --help |
	sed -n '/^SUBCOMMANDS:/,$p' |
	tail -n+2 |
	while read command desc
	do
	    if [ "$command" = help ]; then
		continue
	    fi

	    printf "\n## Subcommand $command\n\n"
	    begin_code
	    sq $command --help
	    end_code
	done
) | quote

printf '\ninclude!("main.rs");\n'
