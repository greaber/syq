# Shared site fonts

Latin subsets of Manrope (headings and navigation), Newsreader (prose), and
IBM Plex Mono (commands and numbers, regular and semibold). All are under
the SIL Open Font License 1.1; the license files travel with the fonts.

`fonts.css` uses mdBook resource placeholders so its asset hashing works.
The benchmark renderer replaces those same placeholders with data URIs,
keeping generated reports self-contained. Keep this directory identical to
`theme/fonts/` in syq. See the site branding maintenance notes in each repo.
