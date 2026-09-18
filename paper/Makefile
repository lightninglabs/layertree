all: main.pdf
listings: ../tools/gen_structured.py ../tools/layertree_scripts.py ../tools/layertree_mid.py ../tools/layertree_min.py
	python3 ../tools/gen_structured.py
main.pdf: main.tex refs.bib appendix-*.tex listings
	latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
clean:
	latexmk -C; rm -f *.bbl *.run.xml
.PHONY: all clean listings
