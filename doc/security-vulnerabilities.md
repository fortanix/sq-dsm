This document describes our process for handling security
vulnerabilities.  At the end of the document there is a list of
projects, and organizations who should be contacted.  If you would
like to be added to this list, please send a mail to
<security@sequoia-pgp.org> (6EFC2689882874C31E4FC4EC4D66CB0FEBA5DAF1),
mention your affiliation, and include an OpenPGP certificate.

# Reporting

Security-sensitive issues should be reported either via:

  - an email to security@sequoia-pgp.org, which is encrypted to
    6EFC2689882874C31E4FC4EC4D66CB0FEBA5DAF1.

  - a gitlab confidential issue
    - https://gitlab.com/sequoia-pgp/sequoia/-/issues/new
    - Tick: "This issue is confidential...", which is just below
      the issue's description.

If someone publishes a security-sensitive issue (including creating a
public issue), then it may be necessary to forego responsible
disclosure, and publish a fix as soon as possible.

If you responsibly disclose a security vulnerability, you may be
eligible for a reward as part of our [bug bounty program].  The bug
bounty program is hosted by [YesWeHack], and sponsored by the
[Sovereign Tech Fund]’s [Bug Resilience Program].  *We prefer that you
report any issues directly to us* as described above to limit the
number of people who know about it.  After we confirm that the
vulnerability is eligible for a reward, you will be paid out via the
YesWeHack platform; you do not need to report the vulnerability via
YesWeHack to be eligible.

  [bug bounty program]: https://yeswehack.com/programs/sequoia-pgp-bug-bounty-program
  [YesWeHack]: https://yeswehack.com
  [Sovereign Tech Fund]: https://www.sovereigntechfund.de/
  [Bug Resilience Program]: https://www.sovereigntechfund.de/programs/bug-resilience

# Resolution

  1. Assess the impact of the issue:

     - Questions to consider:
       - What does an attacker need to trigger the issue?
       - What happens?  (abort? out-of-bounds read? out-of-bounds write?)

     - One approach for coming up with a severity is the Common
       Vulnerability Scoring System
       https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System

     - Current heuristic (improve this based on feedback and experience):
       - Low severity: denial of service
       - High severity: exfiltration of plaintext, exfiltration of
         secret key material, RCE

  1. Create and test a minimal patch

     - Candidate versions:
       - The latest version (always)
       - The version in Debian stable
       - The version in Debian testing, if testing is frozen
       - Minor versions before an MSRV bump (i.e., if 1.x bumps the MSRV
         consider patching 1.x-1).
       - Downstreams may request patches for specific versions.
         If approved, add them to this list.  (Note: companies should be a
         partner, or have a support contract with us.)

     - Suggestions:
       - For testing purposes, gather all tests into a single file.  It
         is then easy to drop the test into any version of the code
         base and see if it is affected.
       - Because we want the patch to cleanly apply to many versions,
         don't append new tests to a sequence of unit tests.  This is
         because the unit tests are normally appended to, and this will
         very likely result in a merge conflict with earlier versions.
         Either prepend the test, or add it to a new file.

  1. Reach out to downstreams (see list below):

     - Inform them of the vulnerability
       - If the severity is greater than low, only inform them via a
         secure channel.  If no encryption key is available, only inform
         them on the flag day.
       - A list of all recipients can be obtained via

             egrep -o '<.*@.*>' doc/security-vulnerabilities.md \
             | grep -v sequoia-pgp.org | xargs echo | sed 's/ /, /g'

     - Share the analysis, and the patch.
     - Ask who needs an update for an old version, and who is happy
       with a new version.
     - For vulnerabilities that are higher than low severity,
       coordinate a flag day (suggest two weeks).

  1. Request a CVE ID
     - This is optional for low-severity issues
     - https://cve.mitre.org/cve/request_id.html

  1. On the flag day:
     - Release new versions of impacted software.
       - Depending on downstream needs, also release new versions of
         software still in use.  That said, most distributions are
         able to carry patches.

     - If the severity is high or critical, yank the impacted crates
       from crates.io
       https://doc.rust-lang.org/cargo/commands/cargo-yank.html
       - As a general rule of thumb, we do not want to yank crates, as
         that can break downstream users who may not even be impacted
         by a vulnerability.
     - Inform any downstreams with whom we are not able to
       communicate with securely.
     - Report the vulnerability to RustSec
       https://github.com/RustSec/advisory-db/blob/main/CONTRIBUTING.md
     - Send email to:
       - announce@lists.sequoia-pgp.org, devel@lists.sequoia-pgp.org,
         oss-security@lists.openwall.com
       - Credit the security researcher who did a responsible disclosure
         with a thank you note in the release announcement.

  1. After flag day:
     - Make confidential issues public.

# Downstream Projects

These are the third-parties that package sequoia-openpgp as part of a
distribution, or integrate it into their software.

## Distributions

  - Debian
    - https://tracker.debian.org/pkg/rust-sequoia-openpgp
    - Maintainer(s):
      - Daniel Kahn Gillmor <dkg@fifthhorseman.net>
        C29F8A0C01F35E34D816AA5CE092EB3A5CA10DBA

  - Fedora
    - https://packages.fedoraproject.org/pkgs/rust-sequoia-openpgp/
    - Maintainer(s):
      - Fabio Valentini <decathorpe@gmail.com>
        2DDA2507B511C02AF9EAC16F5AC5F572E5D410AF

  - Alpine
    - https://pkgs.alpinelinux.org/package/edge/testing/x86_64/sequoia-sq
    - https://pkgs.alpinelinux.org/package/edge/testing/x86_64/sequoia-sqv
    - https://pkgs.alpinelinux.org/package/edge/testing/x86_64/sequoia-chameleon-gnupg
    - Maintainers:
      - Simon Rupf <simon@rupf.net>
        F632C5674E1175B5DC973D0554344C2E06369747

  - Arch
    - https://archlinux.org/groups/x86_64/sequoia/
    - Maintainers:
      - David Runge <dvzrv@archlinux.org>
        C7E7849466FE2358343588377258734B41C31549
      - Levente Polyak <anthraxx@archlinux.org>
        E240B57E2C4630BA768E2F26FC1B547C8D8172C8

  - Gentoo
    - https://packages.gentoo.org/packages/app-crypt/sequoia-sq
    - https://packages.gentoo.org/packages/app-crypt/sequoia-sqv
    - https://packages.gentoo.org/packages/app-crypt/sequoia-chameleon-gnupg
    - Maintainers:
      - Florian Schmaus <flow@gentoo.org>
        1357B01865B2503C18453D208CAC2A9678548E35
      - Sam James <sam@gentoo.org>
        5EF3A41171BB77E6110ED2D01F3D03348DB1A3E2

  - Void Linux
      - https://github.com/void-linux/void-packages/tree/master/srcpkgs/sequoia-sq
      - Maintainers
        - Jan Christian Grünhage <jan.christian@gruenhage.xyz>
          09E8418B46B53B0F825DE4BE018ACF465280F466

  - Red Hat
    - https://access.redhat.com/security/team/contact
    - Only contact if the affected software is shipped as part of a RHEL
      release.
    - Maintainers:
      - SKIP: <secalert@redhat.com>
        77E79ABE93673533ED09EBE2DCE3823597F5EAC4

## Applications

  - pEpEngine
    - https://codeberg.org/pEp/pEpEngine
    - Maintainers:
      - Volker Birk <vb@pep-project.org>
        AAB978A882B9A6E793960B071ADFC82AC3586C14
      - Luca Saiu <positron@pep-project.org>
        C6CEFDA5AC078B88763DCF4DAA22EB64FB14DF25

  - Hagrid
    - https://gitlab.com/keys.openpgp.org/hagrid
    - https://keys.openpgp.org/
    - Maintainers:
      - Vincent Breitmoser <look@my.amazin.horse>
        D4AB192964F76A7F8F8A9B357BD18320DEADFA11
      - <board@keys.openpgp.org>
        31DE97F4781AED87F1EB73E890E0B0D1DBD197F4

  - AnonAddy
    - https://anonaddy.com/
    - https://gitlab.com/willbrowning/anonaddy-sequoia
    - Maintainers:
      - Will Browning <contact@anonaddy.com>
        5FCAFD8A67D2A783CFF4D0E31AC6D923E6FB4EF7

  - JohnnyCanEncrypt
    - https://github.com/kushaldas/johnnycanencrypt
    - Maintainers:
      - Kushal Das <mail@kushaldas.in>
        A85FF376759C994A8A1168D8D8219C8C43F6C5E1

  - RPM
    - https://github.com/rpm-software-management/rpm
    - Maintainers:
      - Panu Matilainen <pmatilai@redhat.com>
        No OpenPGP key.

  - sett
    - https://gitlab.com/biomedit/sett-rs
    - Maintainers:
      - Jaroslaw Surkont <jaroslaw.surkont@unibas.ch>
        AAABFBC698539AB6CE60BDBE8220117C2F906548
      - Christian Ribeaud <christian.ribeaud@karakun.com>
        095F7F80127F704CDC0CA991B24CE13C32FCE9B4
      - Robin Engler <robin.engler@sib.swiss>
        D99AD936FC83C9BABDE7C33E1CF8C1A2076818C3

  - Proxmox
    - Security contact:
      - <security@proxmox.com>
        E6792AA698E11855375AB9E35D0CBD4361F204C5

  - Qubes
    - Security contact:
      - <security@qubes-os.org>
        B35B2DA4B9F9F10949226F77ACC2602F3F48CB21

  - SecureDrop
    - Security contact:
      - <security@freedom.press>
        734F6E707434ECA6C007E1AE82BD6C9616DABB79

  - Hushline
    - No email-based security contact.
    - https://tips.hushline.app/submit_message/scidsg
    - Maintainers:
      - <micah@micahflee.com>

  - dpkg
    - Maintainers:
      - <guillem@debian.org>
        4F3E74F436050C10F5696574B972BF3EA4AE57A3

  - Apertis
    - Security contact:
      - <security@apertis.org>

  - Greenbone OpenVAS
    - Security contact:
      - <security@greenbone.net>
        60DF863C7526ABDA1FB5CB87AF9494DA4F56EBAF

  - CSAF Walker
    - No known security contact.
