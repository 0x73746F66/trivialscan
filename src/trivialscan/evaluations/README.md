The following are negative modifiers and their meaning;

| Score |    Severity     |                                                                                                                                          Rationale |
| ----- | :-------------: | -------------------------------------------------------------------------------------------------------------------------------------------------: |
| 0     | Inconsequential |                                                                                                                                 0 is informational |
| 50    |      Minor      |                                                           Less than 50 would be unproven, over is proven to be a minor risk or very low occurrence |
| 100   |    Moderate     | Most issues at this level are documented and may not occur as often now as before but certainly target vulnerable victims when exposures are found |
| 200   |    Critical     |                         These are not 'if' but 'when' will you be attacked. Many at this level should actually be considered 'assumed compromised' |

For each failure with a negative modifier there may be a corresponding warning with slightly less score impact, or pass modifier that boosts the score a little with a positive modifier.

These use the following table;

| Failure was | Pass is  | Warning is |
| ----------- | :------: | ---------: |
| 0-50        |  + 0-35  |       0-25 |
| 50-100      | + 35-75  |      25-60 |
| 100-200     | + 75-150 |     60-120 |
