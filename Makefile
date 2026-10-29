.PHONY: all keygen e01 lab1 lab2 clean backend

PY ?= python3

all: keygen e01 lab1 lab2

backend:
	$(PY) lab/pqc_common.py

keygen:
	$(PY) lab/keygen.py

e01:
	$(PY) challenges/e01_size_matters/generate_instance.py
	$(PY) challenges/e01_size_matters/solve.py

lab1:
	$(PY) lab/lab1_representation_confusion.py

lab2:
	$(PY) lab/lab2_hybrid_downgrade.py

clean:
	rm -f samples/* challenges/e01_size_matters/instance.json \
	      challenges/e01_size_matters/*.pem challenges/e01_size_matters/*.raw
	find . -name __pycache__ -type d -exec rm -rf {} +
