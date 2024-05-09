# Composite Keys and Signatures Internet-Draft

NOTE: the name of this repo should be changed to "draft-xxxxx-pq-composite-sigs" to better reflect the contents.

## Setting up a build environment

There may be a way to do this in cygwin, but I cut losses and did it in ubuntu:

    $ sudo apt-get install ruby-full
    $ sudo gem install kramdown-rfc2629
    $ sudo apt-get install xml2rfc


## Using the makefile

We have provided a makefile to build the draft in either pure TXT, or fancy HTML formats:

    $ make txt
    or
    $ make html

The default target will build both:

    $ make

## Building the document from markdown

    // to build straight to an RFC-style .txt:
    $ kdrfc draft-xxxxx-pq-composite-sigs-x509.mkd

    // to produce the intermediary .xml for use with other IETF tools:
    $ kramdown-rfc2629 draft-xxxxx-pq-composite-sigs-x509.mkd > draft-xxxxx-pq-composite-sigs-x509.xml

    // to produce HTML (which has links in the ToC!) use this:
    $ xml2rfc draft-xxxxx-pq-composite-certs-x509.xml --basename draft-xxxxx-pq-composite-certs-x509 --html

## Editing Etiquette

When checking in changes to the document source (`.mkd`), please also check in the modified `.txt` for those who wish to review changes (diffs) in their browser.
