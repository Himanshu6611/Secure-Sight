# Target labels

Project target: **0 legitimate; 1 phishing**.

PhiUSIIL publisher labels have the opposite meaning: **source 1 legitimate -> target 0; source 0 phishing -> target 1**. The conversion is source-specific and mandatory. Unsupported sources raise an error; unknown labels are discarded. No universal conversion for UCI/ARFF or -1 labels is inferred.

Full URL identity includes path, query and fragment. Conflicting normalized URLs use majority vote, with a documented phishing tie. Labels describe the historical source, not a current verification of that site's behavior.

Corrected artifacts: data/v5_1_1, models/v5. Old processed features and model scores are not evidence of accuracy.
