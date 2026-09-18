all: main.pdf
listings: reflow_listings.py ../spec/scripts/*.txt
	python3 reflow_listings.py
main.pdf: main.tex refs.bib appendix-*.tex listings
	latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
clean:
	latexmk -C; rm -f *.bbl *.run.xml
.PHONY: all clean listings
