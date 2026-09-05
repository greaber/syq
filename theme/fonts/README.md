# Shared site fonts

Open Sans provides headings, navigation and prose. Manrope is used for the
blue syq wordmark; IBM Plex Mono is used for commands and numbers.
Open Sans is the mdBook-bundled v17 font (all charsets, normal 400/600/700/800),
under Apache 2.0. Manrope and IBM Plex Mono are Latin subsets under SIL OFL 1.1.
The licenses travel with the fonts.

`fonts.css` uses mdBook resource placeholders so its asset hashing works.
The benchmark renderer replaces those same placeholders with data URIs,
keeping generated reports self-contained. Keep this directory identical to
`theme/fonts/` in syq. See the site branding maintenance notes in each repo.
