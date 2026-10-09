"""Legacy URL training is retired; train the corrected versioned ensemble."""
import pathlib
import sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from ml.corrected_training import main

if __name__=="__main__":
    main()
