# SecureSight technology stack

Python 3.12; Flask/Jinja; vanilla JS/CSS; pandas/NumPy; scikit-learn 1.5.1; joblib/Parquet; dnspython, urllib3 and standard TLS sockets; BeautifulSoup static HTML parsing; Pillow/SciPy image heuristics; Flask-Limiter with Redis required in production.

URL model 5.1.1: grouped OOF logistic regression, random forest and **ExtraTrees**, calibrated with sigmoid on independent domains. XGBoost is not present in the trained bundle. The 97-field schema has 59 learned URL fields and 38 separately observed optional fields.

Dynamic browser analysis and external reputation API integrations are unavailable. Email/image classifiers are optional. There is no database, authentication or persistent scan history. The local server is a loopback development instance, not production hosting.

See [architecture](ARCHITECTURE.md) and [verification](REMEDIATION_20261008.md).
