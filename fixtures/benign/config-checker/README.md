# config-checker (benign fixture)

Exercises a behaviour the other benign fixtures do not: **reading a declared
project configuration file**. The skill lists the one file it reads
(`permissions.files.read: settings.toml`), opens exactly that file, parses it
with the standard library, and prints a report. It writes nothing, has no
network access and touches no credentials.

Expected result: SAFE. A skill that reads a configuration file it declares is
legitimate and must not be flagged.
