all: main.pdf
main.pdf: main.tex refs.bib
	latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
clean:
	latexmk -C; rm -f *.bbl *.run.xml
.PHONY: all clean
