# Login-Risk-Evaluator
This program reads a list of login attempts from a JSON file and checks each attempt to determine its risk level. It looks at things like:
1. What country did the login come from
2. What device was used
3. What time of day the login happened
4. How many failed login attempts happened recently
5. Whether the user has logged in successfully today

Using these things, it gives the login a risk score and labels it as:
1. low risk → allow the login
2. medium risk → ask for MFA (extra verification)
3. high risk → block the login

It also prints out the reasons for the decision.
