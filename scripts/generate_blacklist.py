"""Historical dataset hosts must not be treated as a current verified threat feed."""
import pathlib
import sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from ml.corrected_training import main

if __name__=="__main__":
    sys.argv=["generate_blacklist","--prepare-only"]
    main()
