PATH := $(HOME)/bin:/Library/TeX/texbin:$(PATH)
export PATH

layertree-talk.pdf: layertree-talk.tex ltmacros.tex numbers.tex
	latexmk -pdf -interaction=nonstopmode -halt-on-error layertree-talk.tex

clean:
	latexmk -C layertree-talk.tex
