
A user-roles file is a json object with an array of roles.  A small, sample file is:

```
{
    "roles": 
    [
        {
            "name": "standard user",
            "fraction_of_logins_to_personal_machine": "0.9",
            "fraction_of_non_personal_logins_to_shared_machines": "0.9",
            "recursive_logins_min":  "0",
            "recursive_logins_max":  "2",
            "day_start_hour_min":  "8",
            "day_start_hour_max":  "12",
            "activity_min_logins_per_hour":  "0",
            "activity_max_logins_per_hour":  "5",
            "activity_daily_min_hours":  [ "0", "3", "3", "3", "3", "3", "0" ],
            "activity_daily_max_hours":  [ "2", "10", "10", "10", "10", "6", "2" ],
            "terminals_open":  "2",
	    "workflows": [ 'browse_youtube' ]
        },
    ]
}
```


The fields mean:
`name` -- string. The name of the role, as reference in enterprise.json.
`fraction_of_logins_to_personal_machine` -- float.  The ratio of logins that go to the user's personal machine vs. other machines.
`fraction_of_non_personal_logins_to_shared_machines` -- float.  For logins to non-personal machines, that fraction that go to shared machines vs. non-shared machines.
`recursive_logins_min` -- int.  The minimum number of recursive logins.  Should be 0.  A random number of recursive logins are selected in the range (min,max).
`recursive_logins_max` -- int.  The max number of recursive logins.   A random number of recursive logins are selected in the range (min,max).
`day_start_hour_min` -- int.  The minimum hour when the user can start logging in ("working"), in the range 0-24.  Must be less than max.
`day_start_hour_max` -- int.  The maximum hour when the user can start logging in ("working"), in the range 0-24.  Must be larger than min.
`activity_daily_min_hours` -- array[int].  Mimimum hours worked in a day.
`activity_daily_max_hours` -- array[int].  Maximum hours worked in a day.
`activity_min_logins_per_hour` -- int.  Minimum number of logins per working hour.
`activity_max_logins_per_hour` -- int.  Maximum number of logins per working hour.
`terminals_open` -- int.  How many terminals this user has open simulateously.
`workflows` -- array[str].  The Mitre Caldera Human Plugin workflows to run.  
	See ../Downloads/workflows.zip:app/workflows/*.py for the possible workflows.
