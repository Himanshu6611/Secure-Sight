"""Generate versioned features using the same actual lexical extractor as inference."""
import pathlib
import sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from ml.corrected_training import generate_dataset

if __name__=="__main__":
    generate_dataset()
